package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/internal/utils"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
	"github.com/golang-jwt/jwt/v5"
)

// RegisterVerifyHandler handles verification of magic-link tokens.
func RegisterVerifyHandler(ttlStore *ephemeral.TTLStore, nonceStore *ephemeral.NonceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logging.DebugLog("Registration verify started")

		tokenStr := r.URL.Query().Get("token")
		if tokenStr == "" {
			logging.WarnLog("Registration verify failed: missing token")
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Missing token"})
			return
		}

		// Parse and validate token securely
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if token.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
				logging.WarnLog("Registration verify failed: invalid signing algorithm %s", token.Method.Alg())
				return nil, jwt.ErrSignatureInvalid
			}
			return auth.GetSigningKey().PublicKey, nil
		}, jwt.WithIssuer(config.JWTVerificationIssuer()), jwt.WithValidMethods([]string{"EdDSA"}))

		if err != nil {
			logging.WarnLog("Registration verify failed: token parse error - %v", err)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid or expired token"})
			return
		}

		if !token.Valid {
			logging.WarnLog("Registration verify failed: invalid token")
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid or expired token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			logging.WarnLog("Registration verify failed: invalid claims type")
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid token claims"})
			return
		}

		emailInterface, exists := claims["sub"]
		if !exists {
			logging.WarnLog("Registration verify failed: missing subject claim")
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid subject"})
			return
		}

		email, ok := emailInterface.(string)
		if !ok || strings.TrimSpace(email) == "" {
			logging.WarnLog("Registration verify failed: invalid subject format")
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid subject"})
			return
		}

		emailHash := utils.HashEmail(email)

		if !ttlStore.Exists(email) {
			logging.WarnLog("Registration verify failed: token expired or used [%s]", emailHash)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Token expired or already used"})
			return
		}

		// Clean up the TTL store entry
		ttlStore.Delete(email)
		logging.DebugLog("TTL store entry deleted [%s]", emailHash)

		nonce, err := auth.GenerateNonce()
		if err != nil {
			logging.ErrorLog("Nonce generation failed [%s]: %v", emailHash, err)
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to generate nonce"})
			return
		}

		nonceStore.Set(email, nonce, config.JWTRegistrationExpiresIn()*time.Minute)
		logging.DebugLog("Nonce stored [%s]", emailHash)

		duration := time.Since(start)
		logging.InfoLog("Registration verify success [%s] %v", emailHash, duration)
		respondJSON(w, http.StatusOK, models.VerifyResponse{Nonce: nonce})
	}
}
