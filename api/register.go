package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
)

func RegisterHandler(userStore *store.SQLiteStore, nonceStore *ephemeral.NonceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.RegisterCompleteRequest

		// Decode and sanitize input
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

		// Validate payload
		if err := validate.Struct(req); err != nil {
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Validation failed"})
			return
		}

		// Check for existing user
		if userStore.Exists(req.Email) {
			respondJSON(w, http.StatusConflict, models.ErrorResponse{Error: "User already registered"})
			return
		}

		// Check if nonce exists and matches
		storedNonce, exists := nonceStore.Get(req.Email)
		if !exists || storedNonce != req.Nonce {
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Nonce missing, expired, or does not match"})
			return
		}

		// Verify signature
		valid, err := auth.VerifySignature(req.PublicKey, req.Nonce, req.Signature)
		if err != nil || !valid {
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid signature"})
			return
		}

		// Persist user
		if err := userStore.AddUser(models.User{
			Email:     req.Email,
			Username:  req.Username,
			PublicKey: req.PublicKey,
		}); err != nil {
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to save user"})
			return
		}

		// Clean up nonce
		nonceStore.Delete(req.Email)

		respondJSON(w, http.StatusOK, models.StatusResponse{Status: "ok"})
	}
}
