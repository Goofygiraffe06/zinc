package api

import (
	"encoding/json"
	"net/http"

	"github.com/Goofygiraffe06/zinc/store"
)

type RegisterInitRequest struct {
	Email string `json:"email"`
}

type StatusResponse struct {
	Status string `json:"status"`
}

func RegisterInitHandler(userStore *store.SQLiteStore, sessions *store.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterInitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if userStore.Exists(req.Email) {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}

		if !sessions.Start(req.Email) {
			http.Error(w, "Registration already in progress", http.StatusConflict)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(StatusResponse{Status: "ok"})
	}
}
