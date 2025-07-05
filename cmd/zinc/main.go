package main

import (
	"log"
	"net/http"

	"github.com/Goofygiraffe06/zinc/api"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	router := chi.NewRouter()
	router.Use(middleware.Logger)

	// SQLite and session store setup
	userStore, err := store.NewSQLiteStore("zinc.db")
	if err != nil {
		log.Fatal("Failed to connect to DB:", err)
	}
	sessions := store.NewSessionStore()

	// Routes
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	router.Post("/register/init", api.RegisterInitHandler(userStore, sessions))

	port := ":8000"
	log.Println("ZINC server listening on", port)
	http.ListenAndServe(port, router)
}
