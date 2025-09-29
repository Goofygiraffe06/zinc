package manager

import (
	"context"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/internal/workerpool"
)

// WorkManager provides separate pools for DB, Crypto, and SMTP work.
// This helps to isolate heavy tasks from HTTP handlers and avoid blocking.
type WorkManager struct {
	db     *workerpool.Pool
	crypto *workerpool.Pool
	smtp   *workerpool.Pool
}

// Option configures the WorkManager.
type Option func(*options)

type options struct {
	dbWorkers     int
	cryptoWorkers int
	smtpWorkers   int
	queueSize     int
}

// WithDBWorkers sets the DB worker count.
func WithDBWorkers(n int) Option { return func(o *options) { o.dbWorkers = n } }

// WithCryptoWorkers sets the crypto worker count.
func WithCryptoWorkers(n int) Option { return func(o *options) { o.cryptoWorkers = n } }

// WithSMTPWorkers sets the SMTP worker count.
func WithSMTPWorkers(n int) Option { return func(o *options) { o.smtpWorkers = n } }

// WithQueueSize sets the shared queue size (per pool).
func WithQueueSize(n int) Option { return func(o *options) { o.queueSize = n } }

// NewWorkManager constructs the manager with the given options (or defaults from config).
func NewWorkManager(opts ...Option) *WorkManager {
	o := &options{
		dbWorkers:     config.DBWorkerCount(),
		cryptoWorkers: config.CryptoWorkerCount(),
		smtpWorkers:   config.SMTPWorkerCount(),
		queueSize:     config.WorkerQueueSize(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return &WorkManager{
		db:     workerpool.New("db", o.dbWorkers, o.queueSize),
		crypto: workerpool.New("crypto", o.cryptoWorkers, o.queueSize),
		smtp:   workerpool.New("smtp", o.smtpWorkers, o.queueSize),
	}
}

// Close shuts down all pools.
func (m *WorkManager) Close() {
	if m == nil {
		return
	}
	m.db.Close()
	m.crypto.Close()
	m.smtp.Close()
}

// SubmitDB schedules a database task with a context and optional timeout.
func (m *WorkManager) SubmitDB(fn func(ctx context.Context)) error {
	return m.db.Submit(func(ctx context.Context) { fn(ctx) })
}

// SubmitCrypto schedules a cryptographic task.
func (m *WorkManager) SubmitCrypto(fn func(ctx context.Context)) error {
	return m.crypto.Submit(func(ctx context.Context) { fn(ctx) })
}

// SubmitSMTP schedules an SMTP task.
func (m *WorkManager) SubmitSMTP(fn func(ctx context.Context)) error {
	return m.smtp.Submit(func(ctx context.Context) { fn(ctx) })
}

// RunWithTimeout runs a function respecting a deadline and returns whether it completed.
func RunWithTimeout(parent context.Context, d time.Duration, fn func(ctx context.Context)) bool {
	ctx, cancel := context.WithTimeout(parent, d)
	defer cancel()
	done := make(chan struct{})
	go func() { fn(ctx); close(done) }()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}
