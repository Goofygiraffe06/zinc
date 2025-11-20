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
	"github.com/Goofygiraffe06/zinc/internal/controller"
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
	registry        *controller.VerificationRegistry
	mgr             *manager.WorkManager
	rateLimiter     *rateLimiter
	acceptedCount   int
	maxRecipients   int
	maxMessageBytes int64
	domain          string
	recipientPrefix string
	spfChecker      *SPFChecker
	dkimChecker     *DKIMChecker
	verifyMode      string
	spfEnabled      bool
	dkimEnabled     bool
	messageData     []byte
}

func (s *verifyMailboxSession) Reset() {
	s.from = ""
	s.recipients = s.recipients[:0]
	s.acceptedCount = 0
	s.messageData = nil
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
	// Read message data for SPF/DKIM verification
	messageData, err := readMessageData(r, s.maxMessageBytes)
	if err != nil && err != io.EOF {
		logging.WarnLog("SMTP DATA: error reading message from=%s: %v", s.remoteAddr, err)
		return &smtpcore.SMTPError{Code: 451, EnhancedCode: smtpcore.EnhancedCode{4, 3, 0}, Message: "error reading message"}
	}

	if int64(len(messageData)) >= s.maxMessageBytes {
		logging.WarnLog("SMTP DATA: message size limit exceeded from=%s", s.remoteAddr)
	}

	s.messageData = messageData

	// Perform SPF/DKIM verification if not in unrestricted mode
	if s.verifyMode != "unrestricted" {
		// Extract sender IP from remote address
		senderIP := s.remoteAddr
		if idx := strings.LastIndex(senderIP, ":"); idx >= 0 {
			senderIP = senderIP[:idx]
		}
		// Remove brackets from IPv6 addresses
		senderIP = strings.Trim(senderIP, "[]")

		var spfResult SPFResult = SPFNone
		var dkimResult DKIMResult = DKIMNone
		var verificationFailed bool

		// Perform SPF check
		if s.spfEnabled && s.from != "" {
			ctx := context.Background()
			spfResult, err = s.spfChecker.CheckSPF(ctx, senderIP, s.from)
			if err != nil {
				logging.WarnLog("SMTP SPF check error for from=%s ip=%s: %v", utils.HashEmail(s.from), senderIP, err)
			}

			if spfResult == SPFFail || spfResult == SPFSoftFail {
				verificationFailed = true
				if s.verifyMode == "warn" {
					logging.WarnLog("SMTP SPF verification failed (mode=warn): from=[%s] ip=%s result=%s",
						utils.HashEmail(s.from), senderIP, spfResult.String())
				} else if s.verifyMode == "strict" {
					logging.WarnLog("SMTP SPF verification failed (mode=strict): from=[%s] ip=%s result=%s - rejecting",
						utils.HashEmail(s.from), senderIP, spfResult.String())
					return &smtpcore.SMTPError{
						Code:         550,
						EnhancedCode: smtpcore.EnhancedCode{5, 7, 1},
						Message:      "SPF verification failed",
					}
				}
			} else {
				logging.DebugLog("SMTP SPF check passed: from=[%s] ip=%s result=%s",
					utils.HashEmail(s.from), senderIP, spfResult.String())
			}
		}

		// Perform DKIM check
		if s.dkimEnabled && len(s.messageData) > 0 {
			ctx := context.Background()
			dkimResult, err = s.dkimChecker.CheckDKIM(ctx, s.messageData)
			if err != nil {
				logging.WarnLog("SMTP DKIM check error for from=%s: %v", utils.HashEmail(s.from), err)
			}

			if dkimResult == DKIMFail {
				verificationFailed = true
				if s.verifyMode == "warn" {
					logging.WarnLog("SMTP DKIM verification failed (mode=warn): from=[%s] result=%s",
						utils.HashEmail(s.from), dkimResult.String())
				} else if s.verifyMode == "strict" {
					logging.WarnLog("SMTP DKIM verification failed (mode=strict): from=[%s] result=%s - rejecting",
						utils.HashEmail(s.from), dkimResult.String())
					return &smtpcore.SMTPError{
						Code:         550,
						EnhancedCode: smtpcore.EnhancedCode{5, 7, 1},
						Message:      "DKIM verification failed",
					}
				}
			} else {
				logging.DebugLog("SMTP DKIM check passed: from=[%s] result=%s",
					utils.HashEmail(s.from), dkimResult.String())
			}
		}

		// Log verification summary
		if verificationFailed && s.verifyMode == "warn" {
			logging.InfoLog("SMTP verification warning: from=[%s] ip=%s spf=%s dkim=%s - accepting anyway (mode=warn)",
				utils.HashEmail(s.from), senderIP, spfResult.String(), dkimResult.String())
		}
	}

	// Process each accepted verify address independently.
	if len(s.recipients) == 0 {
		return nil
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
				processVerifyNonce(ctx, nonce, senderEmail, remoteAddr, s.ttlStore, s.registry, s.rateLimiter)
			}) {
				logging.WarnLog("SMTP nonce processing timeout nonce=%s", utils.HashEmail(nonce))
			}
		})
	}
	// Reset after processing to avoid repeated work across messages within same session
	s.Reset()
	return nil
}

func processVerifyNonce(_ context.Context, nonceStr string, senderEmail string, remoteAddr string, ttlStore *ephemeral.TTLStore, registry *controller.VerificationRegistry, rateLimiter *rateLimiter) {
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
	nonceHash := utils.HashEmail(nonceStr)

	// Verify sender email matches expected email from registration request
	expectedEmailKey := "expected:" + nonceStr
	expectedEmail, exists := ttlStore.Get(expectedEmailKey)
	if !exists {
		logging.WarnLog("SMTP verify failed: no registration pending for nonce [%s]", nonceHash)
		return
	}

	// Normalize expected email for comparison
	expectedEmail = strings.ToLower(strings.TrimSpace(expectedEmail))

	if senderEmail != expectedEmail {
		logging.WarnLog("SMTP verify failed: email mismatch sender=[%s] expected=[%s] nonce=[%s]",
			utils.HashEmail(senderEmail), utils.HashEmail(expectedEmail), nonceHash)
		return
	}

	logging.DebugLog("SMTP verify: sender validated [%s] nonce=[%s]", emailHash, nonceHash)

	// CRITICAL: Store the verified email in TTLStore BEFORE firing the interrupt
	// The API handler will wake up and immediately check this mapping
	if err := ttlStore.SetWithValue(nonceStr, senderEmail, 3*time.Minute); err != nil {
		logging.ErrorLog("SMTP verify failed: ttl store [%s] nonce=[%s]: %v", emailHash, nonceHash, err)
		return
	}

	logging.DebugLog("SMTP verify: stored proof [%s] nonce=[%s]", emailHash, nonceHash)

	// Now fire the interrupt to wake up the waiting HTTP handler
	registry.Notify(nonceStr)

	logging.InfoLog("SMTP verify success [%s] nonce=[%s]", emailHash, nonceHash)
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
	registry    *controller.VerificationRegistry
	mgr         *manager.WorkManager
	rateLimiter *rateLimiter
	domain      string
	spfChecker  *SPFChecker
	dkimChecker *DKIMChecker
}

func NewBackend(ttl *ephemeral.TTLStore, registry *controller.VerificationRegistry, mgr *manager.WorkManager, domain string) *Backend {
	return &Backend{
		ttlStore:    ttl,
		registry:    registry,
		mgr:         mgr,
		rateLimiter: newRateLimiter(10, 5*time.Minute),
		domain:      domain,
		spfChecker:  NewSPFChecker(),
		dkimChecker: NewDKIMChecker(),
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
		registry:        b.registry,
		mgr:             b.mgr,
		rateLimiter:     b.rateLimiter,
		maxRecipients:   config.SMTPMaxRecipients(),
		maxMessageBytes: int64(config.SMTPMaxMessageBytes()),
		domain:          b.domain,
		recipientPrefix: config.SMTPRecipientPrefix(),
		spfChecker:      b.spfChecker,
		dkimChecker:     b.dkimChecker,
		verifyMode:      config.SMTPVerificationMode(),
		spfEnabled:      config.SMTPSPFEnabled(),
		dkimEnabled:     config.SMTPDKIMEnabled(),
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
