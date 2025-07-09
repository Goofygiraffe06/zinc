package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
	"github.com/golang-jwt/jwt/v5"
)

// RegisterVerifyHandler handles verification of magic-link tokens.
func RegisterVerifyHandler(ttlStore *ephemeral.TTLStore, nonceStore *ephemeral.NonceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.URL.Query().Get("token")
		if tokenStr == "" {
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Missing token"})
			return
		}

		// Parse and validate token securely
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(config.JWTSecret()), nil
		}, jwt.WithIssuer(config.JWTVerificationIssuer()), jwt.WithValidMethods([]string{"HS256"}))

		if err != nil || !token.Valid {
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid or expired token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid token claims"})
			return
		}

		email, ok := claims["sub"].(string)
		if !ok || strings.TrimSpace(email) == "" {
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid subject"})
			return
		}

		if !ttlStore.Exists(email) {
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Token expired or already used"})
			return
		}

		ttlStore.Delete(email)

		nonce, err := auth.GenerateNonce()
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to generate nonce"})
			return
		}

		nonceStore.Set(email, nonce, config.JWTRegistrationExpiresIn()*time.Minute)

		respondJSON(w, http.StatusOK, models.VerifyResponse{Nonce: nonce})
	}
}
