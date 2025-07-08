package api

import (
	"net/http"
	"strings"

	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/golang-jwt/jwt/v5"
)

type VerifyResponse struct {
	Nonce string `json:"nonce"`
}

// RegisterVerifyHandler handles verification of magic-link tokens.
func RegisterVerifyHandler(ephemeral *store.EphemeralStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.URL.Query().Get("token")
		if tokenStr == "" {
			respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Missing token"})
			return
		}

		// Parse and validate token securely
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			// Enforce correct algorithm (HS256)
			if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(config.JWTSecret()), nil
		}, jwt.WithIssuer(config.JWTVerificationIssuer()), jwt.WithValidMethods([]string{"HS256"}))

		if err != nil || !token.Valid {
			respondJSON(w, http.StatusForbidden, ErrorResponse{Error: "Invalid or expired token"})
			return
		}

		// Extract and validate email from subject
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			respondJSON(w, http.StatusForbidden, ErrorResponse{Error: "Invalid token claims"})
			return
		}

		email, ok := claims["sub"].(string)
		if !ok || strings.TrimSpace(email) == "" {
			respondJSON(w, http.StatusForbidden, ErrorResponse{Error: "Invalid subject"})
			return
		}

		if !ephemeral.Exists(email) {
			respondJSON(w, http.StatusForbidden, ErrorResponse{Error: "Token expired or already used"})
			return
		}

		ephemeral.Delete(email)

		nonce, err := auth.GenerateNonce()
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to generate nonce"})
			return
		}

		respondJSON(w, http.StatusOK, VerifyResponse{Nonce: nonce})
	}
}
