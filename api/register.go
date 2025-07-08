package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

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

func RegisterInitHandler(userStore *store.SQLiteStore, ephemeral *store.EphemeralStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterInitRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
			respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON"})
			return
		}

		req.Email = strings.TrimSpace(req.Email)

		if err := validate.Struct(req); err != nil {
			respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid email address"})
			return
		}

		if userStore.Exists(req.Email) {
			respondJSON(w, http.StatusConflict, ErrorResponse{Error: "User already exists"})
			return
		}

		if ephemeral.Exists(req.Email) {
			respondJSON(w, http.StatusConflict, ErrorResponse{Error: "Verification already pending"})
			return
		}

		token, err := auth.GenerateMagicToken(req.Email)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to generate token"})
			return
		}

		if err := ephemeral.Set(req.Email, 3*time.Minute); err != nil {
			switch err {
			case store.ErrTooLong:
				respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Email too long"})
			case store.ErrStoreFull:
				respondJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "Server busy, try again later"})
			default:
				respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Internal error"})
			}
			return
		}

		respondJSON(w, http.StatusOK, map[string]string{"token": token})
	}
}

func respondJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}
