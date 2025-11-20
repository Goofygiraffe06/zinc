package main

import (
	"net/http"
	"os"
	"time"

	"github.com/Goofygiraffe06/zinc/api"
	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/internal/controller"
	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/manager"
	smtpserver "github.com/Goofygiraffe06/zinc/internal/smtp"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func RequestLogger() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			duration := time.Since(start)

			logMsg := "%s %s %d %v"
			args := []interface{}{r.Method, r.URL.Path, ww.Status(), duration}

			switch {
			case ww.Status() >= 500:
				logging.ErrorLog(logMsg, args...)
			case ww.Status() >= 400:
				logging.WarnLog(logMsg, args...)
			default:
				logging.InfoLog(logMsg, args...)
			}
		}
		return http.HandlerFunc(fn)
	}
}

// MaxBytes limits the size of request bodies to prevent abuse.
func MaxBytes(n int64) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && n > 0 {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func main() {
	startTime := time.Now()

	logFile := "zinc.log"
	f, err := logging.InitLogger(logFile)
	if err != nil {
		panic("FATAL: Logger initialization failed - cannot continue without logging capability: " + err.Error())
	}
	defer func() {
		if err := f.Close(); err != nil {
			panic("Failed to close log file: " + err.Error())
		}
	}()

	logging.InfoLog("ZINC Authentication Server starting")
	logging.InfoLog("Process ID: %d, Log file: %s", os.Getpid(), logFile)

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(RequestLogger())
	router.Use(MaxBytes(config.MaxRequestBodyBytes()))

	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	auth.InitSigningKey()

	dbFile := "zinc.db"
	if _, err := os.Stat(dbFile); err == nil {
		if err := os.Chmod(dbFile, 0600); err != nil {
			logging.ErrorLog("SECURITY WARNING: Failed to set restrictive permissions on database file %s: %v", dbFile, err)
			logging.ErrorLog("Database may be readable by other users - manual intervention required")
		} else {
			logging.InfoLog("Database file permissions secured: %s (mode: 0600)", dbFile)
		}
	}

	ttlStore := ephemeral.NewTTLStore()
	nonceStore := ephemeral.NewNonceStore()

	// Create the shared verification registry for interrupt-based registration
	verificationRegistry := controller.NewVerificationRegistry()
	logging.InfoLog("Verification registry initialized")

	mgr := manager.NewWorkManager(
		manager.WithDBWorkers(config.DBWorkerCount()),
		manager.WithCryptoWorkers(config.CryptoWorkerCount()),
		manager.WithSMTPWorkers(config.SMTPWorkerCount()),
	)
	defer mgr.Close()

	userStore, err := store.NewSQLiteStore(dbFile)
	if err != nil {
		logging.FatalLog("CRITICAL: Database connection failed - service cannot start: %v", err)
	}

	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"zinc-auth","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	})

	// API routes - new interrupt-based registration flow
	router.Post("/register/init", api.RegisterInitHandler())
	router.Post("/register", api.RegisterHandler(userStore, ttlStore, verificationRegistry, mgr))

	// SMTP server with shared registry for firing interrupts
	smtpBackend := smtpserver.NewBackend(ttlStore, verificationRegistry, mgr, config.SMTPDomain())
	smtpSrv := smtpserver.NewServer(smtpBackend)
	if err := smtpSrv.Start(); err != nil {
		logging.ErrorLog("SMTP server failed to start: %v", err)
	} else {
		defer smtpSrv.Stop()
	}

	port := ":" + config.GetEnv("PORT", "8080")
	totalStartupTime := time.Since(startTime)

	logging.InfoLog("ZINC server startup completed in %v", totalStartupTime)
	logging.InfoLog("Server ready - listening on port %s", port)

	srv := &http.Server{
		Addr:              port,
		Handler:           router,
		ReadTimeout:       config.ServerReadTimeout(),
		ReadHeaderTimeout: config.ServerReadHeaderTimeout(),
		WriteTimeout:      config.ServerWriteTimeout(),
		IdleTimeout:       config.ServerIdleTimeout(),
	}

	if err := srv.ListenAndServe(); err != nil {
		logging.FatalLog("HTTP server failed to start or encountered fatal error: %v", err)
	}
}
