package smtpserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/manager"
	"github.com/Goofygiraffe06/zinc/internal/utils"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
	smtpcore "github.com/emersion/go-smtp"
	"github.com/golang-jwt/jwt/v5"
)

// verifyMailboxSession implements the SMTP session for the verification listener.
type verifyMailboxSession struct {
	remoteAddr      string
	from            string
	recipients      []string
	ttlStore        *ephemeral.TTLStore
	nonceStore      *ephemeral.NonceStore
	mgr             *manager.WorkManager
	acceptedCount   int
	maxRecipients   int
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
	// Accept only addresses verify+<token>@domain
	// We ignore case for local-part prefix, but require domain match.
	local, dom := splitAddress(to)
	if !domainEquals(dom, s.domain) {
		// Fail gracefully: pretend accepted to avoid enumeration but do not process
		logging.DebugLog("SMTP RCPT ignored: wrong domain=%s from=%s", dom, s.remoteAddr)
		return nil
	}

	// local should be like: prefix+token
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
	buf := make([]byte, 4096)
	for {
		_, err := r.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			// Any read error at this point is non-fatal for our flow.
			break
		}
		// We don't store the data; loop continues until EOF or error.
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
		token := strings.TrimSpace(parts[1])
		if token == "" {
			continue
		}

		// Process token asynchronously on SMTP pool with a bounded timeout.
		_ = s.mgr.SubmitSMTP(func(ctx context.Context) {
			// Bound total processing time per token
			if !manager.RunWithTimeout(ctx, 3*time.Second, func(ctx context.Context) {
				processVerifyToken(ctx, token, s.ttlStore, s.nonceStore)
			}) {
				logging.WarnLog("SMTP token processing timeout token=%s", utils.HashEmail(token))
			}
		})
	}
	// Reset after processing to avoid repeated work across messages within same session
	s.Reset()
	return nil
}

// processVerifyToken mirrors the logic of api.RegisterVerifyHandler, using the JWT token
// in the plus-address to locate the email subject, validate TTL presence, and issue a nonce.
func processVerifyToken(_ context.Context, tokenStr string, ttlStore *ephemeral.TTLStore, nonceStore *ephemeral.NonceStore) {
	// Parse and validate token
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			return nil, jwt.ErrSignatureInvalid
		}
		return auth.GetSigningKey().PublicKey, nil
	}, jwt.WithIssuer(config.JWTVerificationIssuer()), jwt.WithValidMethods([]string{"EdDSA"}))
	if err != nil || !token.Valid {
		logging.WarnLog("SMTP verify failed: invalid token")
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		logging.WarnLog("SMTP verify failed: invalid claims")
		return
	}
	emailInterface, exists := claims["sub"]
	if !exists {
		logging.WarnLog("SMTP verify failed: missing subject")
		return
	}
	email, ok := emailInterface.(string)
	if !ok || strings.TrimSpace(email) == "" {
		logging.WarnLog("SMTP verify failed: invalid subject format")
		return
	}
	email = strings.ToLower(strings.TrimSpace(email))
	emailHash := utils.HashEmail(email)

	if !ttlStore.Exists(email) {
		logging.WarnLog("SMTP verify failed: token expired or used [%s]", emailHash)
		return
	}
	// Clean up the TTL store entry and use the token itself as the nonce.
	// This lets the client sign the token and complete registration without an HTTP verify step.
	ttlStore.Delete(email)
	nonce := tokenStr
	if err := nonceStore.Set(email, nonce, config.JWTRegistrationExpiresIn()*time.Minute); err != nil {
		logging.ErrorLog("SMTP verify failed: nonce store [%s]: %v", emailHash, err)
		return
	}
	logging.InfoLog("SMTP verify success [%s]", emailHash)
}

// Backend implements the SMTP Backend for go-smtp.
type Backend struct {
	ttlStore   *ephemeral.TTLStore
	nonceStore *ephemeral.NonceStore
	mgr        *manager.WorkManager
	domain     string
}

func NewBackend(ttl *ephemeral.TTLStore, nonce *ephemeral.NonceStore, mgr *manager.WorkManager, domain string) *Backend {
	return &Backend{ttlStore: ttl, nonceStore: nonce, mgr: mgr, domain: domain}
}

func (b *Backend) NewSession(c *smtpcore.Conn) (smtpcore.Session, error) {
	ra := ""
	sess := &verifyMailboxSession{
		remoteAddr:      ra,
		ttlStore:        b.ttlStore,
		nonceStore:      b.nonceStore,
		mgr:             b.mgr,
		maxRecipients:   config.SMTPMaxRecipients(),
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
	s.Server.ReadTimeout = 5 * time.Second
	s.Server.WriteTimeout = 5 * time.Second
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
