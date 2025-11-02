package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/manager"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/internal/utils"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

func RegisterInitHandler(userStore *store.SQLiteStore, ttlStore *ephemeral.TTLStore, mgr *manager.WorkManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		var req models.RegisterInitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
			logging.WarnLog("Registration init failed: invalid request")
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Invalid JSON"})
			return
		}

		req.Email = strings.ToLower(strings.TrimSpace(req.Email))
		emailHash := utils.HashEmail(req.Email)

		if err := validate.Struct(req); err != nil {
			logging.WarnLog("Registration init failed: invalid email [%s]", emailHash)
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Invalid email address"})
			return
		}

		if userStore.Exists(req.Email) {
			logging.WarnLog("Registration init failed: user exists [%s]", emailHash)
			respondJSON(w, http.StatusConflict, models.ErrorResponse{Error: "User already exists"})
			return
		}

		if ttlStore.Exists(req.Email) {
			logging.WarnLog("Registration init failed: verification pending [%s]", emailHash)
			respondJSON(w, http.StatusConflict, models.ErrorResponse{Error: "Verification already pending"})
			return
		}

		nonce, err := generateRegistrationNonce()
		if err != nil {
			logging.ErrorLog("Registration init failed: nonce generation [%s]: %v", emailHash, err)
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to generate nonce"})
			return
		}

		if err := ttlStore.Set(req.Email+":"+nonce, config.JWTRegistrationExpiresIn()*time.Minute); err != nil {
			logging.ErrorLog("Registration init failed: store error [%s]: %v", emailHash, err)
			switch err {
			case ephemeral.ErrTooLong:
				respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Email too long"})
			case ephemeral.ErrStoreFull:
				respondJSON(w, http.StatusServiceUnavailable, models.ErrorResponse{Error: "Server busy, try again later"})
			default:
				respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Internal error"})
			}
			return
		}

		duration := time.Since(start)
		logging.InfoLog("Registration init success [%s] %v", emailHash, duration)
		respondJSON(w, http.StatusOK, models.NonceResponse{Nonce: nonce})
	}
}

// generateRegistrationNonce creates a cryptographically secure 32-byte nonce for registration
func generateRegistrationNonce() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func respondJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logging.ErrorLog("JSON encoding failed: %v", err)
	}
}
