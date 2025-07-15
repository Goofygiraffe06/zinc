package main

import (
	"log"
	"net/http"
	"os"

	"github.com/Goofygiraffe06/zinc/api"
	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	router := chi.NewRouter()
	router.Use(middleware.Logger)

	//Initilalize Signing Keys
	auth.InitSigningKey()
	// Set restrictive permissions for the SQLite database file if it exists
	dbFile := "zinc.db"
	if _, err := os.Stat(dbFile); err == nil {
		if err := os.Chmod(dbFile, 0600); err != nil {
			log.Printf("Warning: failed to set restrictive permissions on %s: %v", dbFile, err)
		}
	}
	// Initialize ephemeral stores
	ttlStore := ephemeral.NewTTLStore()
	nonceStore := ephemeral.NewNonceStore()

	// SQLite setup
	userStore, err := store.NewSQLiteStore("zinc.db")
	if err != nil {
		log.Fatal("Failed to connect to DB:", err)
	}

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
	log.Println("ZINC server listening on", port)
	if err := http.ListenAndServe(port, router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
