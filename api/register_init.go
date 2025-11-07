package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

func RegisterInitHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Generate a cryptographically secure nonce - completely stateless
		nonce, err := generateRegistrationNonce()
		if err != nil {
			logging.ErrorLog("Registration init failed: nonce generation: %v", err)
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to generate nonce"})
			return
		}

		duration := time.Since(start)
		logging.InfoLog("Registration init success %v", duration)
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
