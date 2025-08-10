package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
)

func RegisterHandler(userStore *store.SQLiteStore, nonceStore *ephemeral.NonceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logging.DebugLog("Registration complete started")

		var req models.RegisterCompleteRequest
		// Decode and sanitize input
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logging.WarnLog("Registration complete failed: invalid JSON")
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Invalid JSON"})
			return
		}

		req.Email = strings.TrimSpace(req.Email)
		req.Username = strings.TrimSpace(req.Username)
		req.PublicKey = strings.TrimSpace(req.PublicKey)
		req.Signature = strings.TrimSpace(req.Signature)
		req.Nonce = strings.TrimSpace(req.Nonce)
		req.Username = strings.ToLower(req.Username)
		req.Username = strings.ReplaceAll(req.Username, " ", "")
		req.PublicKey = strings.ReplaceAll(req.PublicKey, "\n", "")
		req.PublicKey = strings.ReplaceAll(req.PublicKey, "\r", "")

		emailHash := utils.hashEmail(req.Email)
		usernameHash := utils.hashUsername(req.Username)

		logging.DebugLog("Registration data sanitized [%s][%s]", emailHash, usernameHash)

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

		// Check if nonce exists and matches
		storedNonce, exists := nonceStore.Get(req.Email)
		if !exists {
			logging.WarnLog("Registration complete failed: nonce missing [%s]", emailHash)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Nonce missing, expired, or does not match"})
			return
		}

		if storedNonce != req.Nonce {
			logging.WarnLog("Registration complete failed: nonce mismatch [%s]", emailHash)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Nonce missing, expired, or does not match"})
			return
		}

		logging.DebugLog("Nonce validated [%s]", emailHash)

		// Verify signature
		sigStart := time.Now()
		valid, err := auth.VerifySignature(req.PublicKey, req.Nonce, req.Signature)
		sigDuration := time.Since(sigStart)

		if err != nil {
			logging.ErrorLog("Signature verification error [%s]: %v (took %v)", emailHash, err, sigDuration)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid signature"})
			return
		}

		if !valid {
			logging.WarnLog("Registration complete failed: invalid signature [%s] (took %v)", emailHash, sigDuration)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid signature"})
			return
		}

		logging.DebugLog("Signature verified [%s] %v", emailHash, sigDuration)

		// Persist user
		dbStart := time.Now()
		if err := userStore.AddUser(models.User{
			Email:     req.Email,
			Username:  req.Username,
			PublicKey: req.PublicKey,
		}); err != nil {
			dbDuration := time.Since(dbStart)
			logging.ErrorLog("User creation failed [%s][%s]: %v (took %v)", emailHash, usernameHash, err, dbDuration)
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to save user"})
			return
		}
		dbDuration := time.Since(dbStart)

		// Clean up nonce
		nonceStore.Delete(req.Email)
		logging.DebugLog("Nonce cleaned up [%s]", emailHash)

		duration := time.Since(start)
		logging.InfoLog("Registration complete success [%s][%s] %v (db: %v, sig: %v)",
			emailHash, usernameHash, duration, dbDuration, sigDuration)
		respondJSON(w, http.StatusOK, models.StatusResponse{Status: "ok"})
	}
}
