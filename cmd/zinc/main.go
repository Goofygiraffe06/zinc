package main

import (
	"net/http"
	"os"
	"time"

	"github.com/Goofygiraffe06/zinc/api"
	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	startTime := time.Now()

	// Initialize logger
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

	// Initialize HTTP router
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)

	// Initialize signing keys
	auth.InitSigningKey()

	// Secure SQLite DB file if it exists
	dbFile := "zinc.db"
	if _, err := os.Stat(dbFile); err == nil {
		if err := os.Chmod(dbFile, 0600); err != nil {
			logging.ErrorLog("SECURITY WARNING: Failed to set restrictive permissions on database file %s: %v", dbFile, err)
			logging.ErrorLog("Database may be readable by other users - manual intervention required")
		} else {
			logging.InfoLog("Database file permissions secured: %s (mode: 0600)", dbFile)
		}
	}

	// Initialize ephemeral stores
	ttlStore := ephemeral.NewTTLStore()
	nonceStore := ephemeral.NewNonceStore()

	// SQLite setup
	userStore, err := store.NewSQLiteStore(dbFile)
	if err != nil {
		logging.FatalLog("CRITICAL: Database connection failed - service cannot start: %v", err)
	}

	// Health check endpoint
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"zinc-auth","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	})

	// API Routes
	router.Post("/register/init", api.RegisterInitHandler(userStore, ttlStore))
	router.Get("/register/verify", api.RegisterVerifyHandler(ttlStore, nonceStore))
	router.Post("/register", api.RegisterHandler(userStore, nonceStore))
	router.Post("/login/init", api.AuthInitHandler(userStore, nonceStore))

	port := ":" + config.GetEnv("PORT", "8080")
	totalStartupTime := time.Since(startTime)

	logging.InfoLog("ZINC server startup completed in %v", totalStartupTime)
	logging.InfoLog("Server ready - listening on port %s", port)

	if err := http.ListenAndServe(port, router); err != nil {
		logging.FatalLog("HTTP server failed to start or encountered fatal error: %v", err)
	}
}
