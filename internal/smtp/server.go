package smtpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/manager"
	"github.com/Goofygiraffe06/zinc/internal/utils"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
	smtpcore "github.com/emersion/go-smtp"
)

// rateLimiter provides simple in-memory rate limiting for verification attempts.
type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	maxRate  int
	window   time.Duration
}

func newRateLimiter(maxRate int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		attempts: make(map[string][]time.Time),
		maxRate:  maxRate,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	timestamps := rl.attempts[key]
	valid := timestamps[:0]
	for _, t := range timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.maxRate {
		rl.attempts[key] = valid
		return false
	}

	valid = append(valid, now)
	rl.attempts[key] = valid
	return true
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-rl.window * 2)

		for key, timestamps := range rl.attempts {
			if len(timestamps) == 0 || timestamps[len(timestamps)-1].Before(cutoff) {
				delete(rl.attempts, key)
			}
		}
		rl.mu.Unlock()
	}
}

// verifyMailboxSession implements the SMTP session for the verification listener.
type verifyMailboxSession struct {
	remoteAddr      string
	from            string
	recipients      []string
	ttlStore        *ephemeral.TTLStore
	nonceStore      *ephemeral.NonceStore
	mgr             *manager.WorkManager
	rateLimiter     *rateLimiter
	acceptedCount   int
	maxRecipients   int
	maxMessageBytes int64
	domain          string
	recipientPrefix string
}

func (s *verifyMailboxSession) Reset() {
	s.from = ""
	s.recipients = s.recipients[:0]
	s.acceptedCount = 0
}

func (s *verifyMailboxSession) Logout() error { return nil }

func (s *verifyMailboxSession) Mail(from string, opts *smtpcore.MailOptions) error {
	s.from = from
	return nil
}

func (s *verifyMailboxSession) Rcpt(to string, _ *smtpcore.RcptOptions) error {
	// Accept only addresses verify+<nonce>@domain
	// We ignore case for local-part prefix, but require domain match.
	local, dom := splitAddress(to)
	if !domainEquals(dom, s.domain) {
		// Fail gracefully: pretend accepted to avoid enumeration but do not process
		logging.DebugLog("SMTP RCPT ignored: wrong domain=%s from=%s", dom, s.remoteAddr)
		return nil
	}

	// local should be like: prefix+nonce
	prefixLower := strings.ToLower(s.recipientPrefix)
	parts := strings.SplitN(local, "+", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != prefixLower {
		logging.DebugLog("SMTP RCPT ignored: not a verify address local=%s", utils.HashEmail(local))
		return nil
	}
	if s.acceptedCount >= s.maxRecipients {
		return &smtpcore.SMTPError{Code: 452, EnhancedCode: smtpcore.EnhancedCode{4, 5, 3}, Message: "too many recipients"}
	}
	s.recipients = append(s.recipients, to)
	s.acceptedCount++
	return nil
}

func (s *verifyMailboxSession) Data(r io.Reader) error {
	// We ignore the message body. We only act based on the accepted RCPTs.
	// Process each accepted verify address independently.
	if len(s.recipients) == 0 {
		return nil
	}

	// Drain up to MaxMessageBytes and then stop, to avoid leaving unread data in the connection.
	// We intentionally ignore content; a small read protects us from giant inputs if server config failed.
	bytesRead, err := io.Copy(io.Discard, io.LimitReader(r, s.maxMessageBytes))
	if err != nil && err != io.EOF {
		logging.WarnLog("SMTP DATA: error draining message from=%s: %v", s.remoteAddr, err)
		return &smtpcore.SMTPError{Code: 451, EnhancedCode: smtpcore.EnhancedCode{4, 3, 0}, Message: "error reading message"}
	}

	if bytesRead >= s.maxMessageBytes {
		logging.WarnLog("SMTP DATA: message size limit exceeded from=%s", s.remoteAddr)
	}

	for _, rcpt := range s.recipients {
		local, dom := splitAddress(rcpt)
		if !domainEquals(dom, s.domain) {
			continue
		}
		parts := strings.SplitN(local, "+", 2)
		if len(parts) != 2 {
			continue
		}
		nonce := strings.TrimSpace(parts[1])
		if nonce == "" {
			continue
		}

		// Capture sender address to verify nonce ownership
		senderEmail := s.from
		remoteAddr := s.remoteAddr

		// Process nonce asynchronously on SMTP pool with a bounded timeout.
		_ = s.mgr.SubmitSMTP(func(ctx context.Context) {
			// Bound total processing time per nonce
			if !manager.RunWithTimeout(ctx, 5*time.Second, func(ctx context.Context) {
				processVerifyNonce(ctx, nonce, senderEmail, remoteAddr, s.ttlStore, s.nonceStore, s.rateLimiter)
			}) {
				logging.WarnLog("SMTP nonce processing timeout nonce=%s", utils.HashEmail(nonce))
			}
		})
	}
	// Reset after processing to avoid repeated work across messages within same session
	s.Reset()
	return nil
}

func processVerifyNonce(_ context.Context, nonceStr string, senderEmail string, remoteAddr string, ttlStore *ephemeral.TTLStore, nonceStore *ephemeral.NonceStore, rateLimiter *rateLimiter) {
	// Normalize sender email
	senderEmail = strings.ToLower(strings.TrimSpace(senderEmail))
	// Strip angle brackets if present
	senderEmail = strings.Trim(senderEmail, "<>")
	senderEmail = strings.TrimSpace(senderEmail)

	if senderEmail == "" {
		logging.WarnLog("SMTP verify failed: invalid sender email from=%s", remoteAddr)
		return
	}

	// Apply rate limiting per sender email to prevent brute force attacks
	if !rateLimiter.allow(senderEmail) {
		logging.WarnLog("SMTP verify failed: rate limit exceeded [%s] from=%s", utils.HashEmail(senderEmail), remoteAddr)
		return
	}

	emailHash := utils.HashEmail(senderEmail)

	// Validate nonce - check if email:nonce combination exists in TTL store
	key := senderEmail + ":" + nonceStr
	if !ttlStore.Exists(key) {
		logging.WarnLog("SMTP verify failed: nonce expired or invalid [%s]", emailHash)
		return
	}

	// Clean up the TTL store entry and generate a cryptographically secure nonce for registration completion
	ttlStore.Delete(key)

	// Generate cryptographically secure random nonce for the actual registration signature
	registrationNonce, err := generateSecureNonce()
	if err != nil {
		logging.ErrorLog("SMTP verify failed: nonce generation [%s]: %v", emailHash, err)
		return
	}

	if err := nonceStore.Set(senderEmail, registrationNonce, config.JWTRegistrationExpiresIn()*time.Minute); err != nil {
		logging.ErrorLog("SMTP verify failed: nonce store [%s]: %v", emailHash, err)
		return
	}
	logging.InfoLog("SMTP verify success [%s]", emailHash)
}

// generateSecureNonce creates a cryptographically secure random nonce.
func generateSecureNonce() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// Backend implements the SMTP Backend for go-smtp.
type Backend struct {
	ttlStore    *ephemeral.TTLStore
	nonceStore  *ephemeral.NonceStore
	mgr         *manager.WorkManager
	rateLimiter *rateLimiter
	domain      string
}

func NewBackend(ttl *ephemeral.TTLStore, nonce *ephemeral.NonceStore, mgr *manager.WorkManager, domain string) *Backend {
	return &Backend{
		ttlStore:    ttl,
		nonceStore:  nonce,
		mgr:         mgr,
		rateLimiter: newRateLimiter(10, 5*time.Minute),
		domain:      domain,
	}
}

func (b *Backend) NewSession(c *smtpcore.Conn) (smtpcore.Session, error) {
	// Extract remote address for logging and rate limiting
	ra := "unknown"
	if c.Conn() != nil {
		ra = c.Conn().RemoteAddr().String()
	}
	sess := &verifyMailboxSession{
		remoteAddr:      ra,
		ttlStore:        b.ttlStore,
		nonceStore:      b.nonceStore,
		mgr:             b.mgr,
		rateLimiter:     b.rateLimiter,
		maxRecipients:   config.SMTPMaxRecipients(),
		maxMessageBytes: int64(config.SMTPMaxMessageBytes()),
		domain:          b.domain,
		recipientPrefix: config.SMTPRecipientPrefix(),
	}
	return sess, nil
}

// Server wraps go-smtp server with configuration.
type Server struct {
	*smtpcore.Server
	ln net.Listener
}

// NewServer constructs and configures the verification SMTP server.
func NewServer(b *Backend) *Server {
	s := &Server{Server: smtpcore.NewServer(b)}
	s.Server.Addr = config.SMTPListenAddr()
	s.Server.Domain = config.SMTPDomain()
	s.Server.ReadTimeout = 10 * time.Second
	s.Server.WriteTimeout = 10 * time.Second
	s.Server.MaxMessageBytes = int64(config.SMTPMaxMessageBytes())
	s.Server.MaxRecipients = config.SMTPMaxRecipients()
	s.Server.AllowInsecureAuth = false
	return s
}

// Start begins listening in a separate goroutine.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.Server.Addr)
	if err != nil {
		return fmt.Errorf("smtp listen failed: %w", err)
	}
	s.ln = ln
	go func() {
		logging.InfoLog("SMTP server listening on %s (domain=%s)", s.Server.Addr, s.Server.Domain)
		if err := s.Server.Serve(ln); err != nil {
			logging.ErrorLog("SMTP server stopped: %v", err)
		}
	}()
	return nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() {
	if s == nil {
		return
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
}

// Helper utilities
func splitAddress(addr string) (local, domain string) {
	addr = strings.TrimSpace(addr)
	// Strip angle brackets if present (e.g., <user@domain> -> user@domain)
	addr = strings.Trim(addr, "<>")
	addr = strings.TrimSpace(addr)
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return addr[:i], addr[i+1:]
	}
	return addr, ""
}

func domainEquals(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
