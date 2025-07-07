package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Goofygiraffe06/zinc/internal/auth"
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

func RegisterInitHandler(userStore *store.SQLiteStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Decode JSON
		var req RegisterInitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
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
		if userStore.Exists(req.Email) {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}

		token, err := auth.GenerateJWT(req.Email)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}
func respondJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}
