package main

import (
	"net/http"
	"os"

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
	// Initialize logger
	f, err := logging.InitLogger("zinc.log")
	if err != nil {
		// If logging fails, we can't even log that error with zerolog, so panic.
		panic("Failed to initialize logger: " + err.Error())
	}
	defer f.Close()

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)

	logging.InfoLog("Starting ZINC server")

	// Initialize signing keys
	auth.InitSigningKey()
	logging.DebugLog("Signing keys initialized")

	// Secure SQLite DB file if it exists
	dbFile := "zinc.db"
	if _, err := os.Stat(dbFile); err == nil {
		if err := os.Chmod(dbFile, 0600); err != nil {
			logging.ErrorLog("Failed to set restrictive permissions on %s: %v", dbFile, err)
		} else {
			logging.DebugLog("Permissions on %s set to 0600", dbFile)
		}
	}

	// Initialize ephemeral stores
	ttlStore := ephemeral.NewTTLStore()
	nonceStore := ephemeral.NewNonceStore()
	logging.DebugLog("Ephemeral stores initialized")

	// SQLite setup
	userStore, err := store.NewSQLiteStore(dbFile)
	if err != nil {
		logging.FatalLog("Failed to connect to DB: %v", err)
	}
	logging.InfoLog("Connected to SQLite database: %s", dbFile)

	// Routes
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	router.Post("/register/init", api.RegisterInitHandler(userStore, ttlStore))
	router.Get("/register/verify", api.RegisterVerifyHandler(ttlStore, nonceStore))
	router.Post("/register", api.RegisterHandler(userStore, nonceStore))
	router.Post("/login/init", api.AuthInitHandler(userStore, nonceStore))

	port := ":" + config.GetEnv("PORT", "8080")
	logging.InfoLog("ZINC server listening on %s", port)

	if err := http.ListenAndServe(port, router); err != nil {
		logging.FatalLog("Server failed: %v", err)
	}
}
