package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

func RegisterInitHandler(userStore *store.SQLiteStore, ephemeral *store.EphemeralStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.RegisterInitRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Invalid JSON"})
			return
		}

		req.Email = strings.TrimSpace(req.Email)

		if err := validate.Struct(req); err != nil {
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Invalid email address"})
			return
		}

		if userStore.Exists(req.Email) {
			respondJSON(w, http.StatusConflict, models.ErrorResponse{Error: "User already exists"})
			return
		}

		if ephemeral.Exists(req.Email) {
			respondJSON(w, http.StatusConflict, models.ErrorResponse{Error: "Verification already pending"})
			return
		}

		token, err := auth.GenerateMagicToken(req.Email)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to generate token"})
			return
		}

		if err := ephemeral.Set(req.Email, config.JWTRegistrationExpiresIn()*time.Minute); err != nil {
			switch err {
			case store.ErrTooLong:
				respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Email too long"})
			case store.ErrStoreFull:
				respondJSON(w, http.StatusServiceUnavailable, models.ErrorResponse{Error: "Server busy, try again later"})
			default:
				respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Internal error"})
			}
			return
		}

		respondJSON(w, http.StatusOK, models.TokenResponse{Token: token})
	}
}

func respondJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}
