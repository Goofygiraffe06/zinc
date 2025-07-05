package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Goofygiraffe06/zinc/store"
	"github.com/go-playground/validator/v10"
)

type RegisterInitRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type StatusResponse struct {
	Status string `json:"status"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

var validate = validator.New()

func RegisterInitHandler(userStore *store.SQLiteStore, sessions *store.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Decode JSON
		var req RegisterInitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON"})
			return
		}

		// Trim email to avoid leading/trailing whitespace
		req.Email = strings.TrimSpace(req.Email)

		// Validate fields
		if err := validate.Struct(req); err != nil {
			respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid email address"})
			return
		}

		// Check for existing user
		if userStore.Exists(req.Email) {
			respondJSON(w, http.StatusConflict, ErrorResponse{Error: "User already exists"})
			return
		}

		// Check if session is already active
		if !sessions.Start(req.Email) {
			respondJSON(w, http.StatusConflict, ErrorResponse{Error: "Registration already in progress"})
			return
		}

		respondJSON(w, http.StatusOK, StatusResponse{Status: "ok"})
	}
}

func respondJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}
