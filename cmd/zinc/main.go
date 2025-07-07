package main

import (
	"log"
	"net/http"

	"github.com/Goofygiraffe06/zinc/api"
	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	router := chi.NewRouter()
	router.Use(middleware.Logger)

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

	router.Post("/register/init", api.RegisterInitHandler(userStore))

	port := ":" + config.GetEnv("PORT", "8080")
	log.Println("ZINC server listening on", port)
	if err := http.ListenAndServe(port, router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
