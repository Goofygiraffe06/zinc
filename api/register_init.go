package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// hashEmail creates a consistent hash for logging without exposing PII
func hashEmail(email string) string {
	hash := sha256.Sum256([]byte(email))
	return hex.EncodeToString(hash[:])[:12]
}

func RegisterInitHandler(userStore *store.SQLiteStore, ttlStore *ephemeral.TTLStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logging.DebugLog("Registration init started")

		var req models.RegisterInitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logging.WarnLog("Registration init failed: invalid JSON")
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Invalid JSON"})
			return
		}

		if req.Email == "" {
			logging.WarnLog("Registration init failed: missing email")
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Invalid JSON"})
			return
		}

		req.Email = strings.ToLower(strings.TrimSpace(req.Email))
		emailHash := hashEmail(req.Email)

		if err := validate.Struct(req); err != nil {
			logging.WarnLog("Registration init failed: invalid email format [%s]", emailHash)
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

		token, err := auth.GenerateMagicToken(req.Email)
		if err != nil {
			logging.ErrorLog("Token generation failed [%s]: %v", emailHash, err)
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to generate token"})
			return
		}

		if err := ttlStore.Set(req.Email, config.JWTRegistrationExpiresIn()*time.Minute); err != nil {
			logging.ErrorLog("TTL store failed [%s]: %v", emailHash, err)
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
		respondJSON(w, http.StatusOK, models.TokenResponse{Token: token})
	}
}

func respondJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logging.ErrorLog("JSON encoding failed: %v", err)
	}
}
