package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/internal/utils"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
)

func RegisterHandler(userStore *store.SQLiteStore, nonceStore *ephemeral.NonceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		var req models.RegisterCompleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logging.WarnLog("Registration complete failed: invalid JSON")
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Invalid JSON"})
			return
		}

		// Sanitize input
		req.Email = strings.TrimSpace(req.Email)
		req.Username = strings.TrimSpace(req.Username)
		req.PublicKey = strings.TrimSpace(req.PublicKey)
		req.Signature = strings.TrimSpace(req.Signature)
		req.Nonce = strings.TrimSpace(req.Nonce)
		req.Username = strings.ToLower(req.Username)
		req.Username = strings.ReplaceAll(req.Username, " ", "")
		req.PublicKey = strings.ReplaceAll(req.PublicKey, "\n", "")
		req.PublicKey = strings.ReplaceAll(req.PublicKey, "\r", "")

		emailHash := utils.HashEmail(req.Email)
		usernameHash := utils.HashUsername(req.Username)

		// Validate payload
		if err := validate.Struct(req); err != nil {
			logging.WarnLog("Registration complete failed: validation error [%s][%s]", emailHash, usernameHash)
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Validation failed"})
			return
		}

		// Check for existing user
		if userStore.Exists(req.Email) {
			logging.WarnLog("Registration complete failed: user exists [%s]", emailHash)
			respondJSON(w, http.StatusConflict, models.ErrorResponse{Error: "User already registered"})
			return
		}

		// Validate nonce
		storedNonce, exists := nonceStore.Get(req.Email)
		if !exists || storedNonce != req.Nonce {
			logging.WarnLog("Registration complete failed: nonce invalid [%s]", emailHash)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Nonce missing, expired, or does not match"})
			return
		}

		// Verify signature
		sigStart := time.Now()
		valid, err := auth.VerifySignature(req.PublicKey, req.Nonce, req.Signature)
		sigDuration := time.Since(sigStart)

		if err != nil {
			logging.ErrorLog("Registration complete failed: signature error [%s]: %v", emailHash, err)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid signature"})
			return
		}

		if !valid {
			logging.WarnLog("Registration complete failed: invalid signature [%s]", emailHash)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid signature"})
			return
		}

		// Create user
		dbStart := time.Now()
		if err := userStore.AddUser(models.User{
			Email:     req.Email,
			Username:  req.Username,
			PublicKey: req.PublicKey,
		}); err != nil {
			logging.ErrorLog("Registration complete failed: database error [%s][%s]: %v", emailHash, usernameHash, err)
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to save user"})
			return
		}
		dbDuration := time.Since(dbStart)

		// Clean up nonce
		nonceStore.Delete(req.Email)

		duration := time.Since(start)
		logging.InfoLog("Registration complete success [%s][%s] %v (db: %v, sig: %v)",
			emailHash, usernameHash, duration, dbDuration, sigDuration)
		respondJSON(w, http.StatusOK, models.StatusResponse{Status: "ok"})
	}
}
