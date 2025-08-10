package auth

import (
	"errors"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/utils"
	"github.com/golang-jwt/jwt/v5"
)

func GenerateMagicToken(email string) (string, error) {
	emailHash := utils.HashEmail(email)

	key := GetSigningKey()
	if key == nil || key.PrivateKey == nil {
		logging.ErrorLog("Magic token generation failed [%s]: Ed25519 key not initialized", emailHash)
		return "", errors.New("Ed25519 key not initialized")
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": &email,
		"iss": config.JWTVerificationIssuer(),
		"exp": now.Add(config.JWTRegistrationExpiresIn()).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenStr, err := token.SignedString(key.PrivateKey)
	if err != nil {
		logging.ErrorLog("Magic token signing failed [%s]: %v", emailHash, err)
		return "", err
	}

	// Only log on debug level for successful operations
	logging.DebugLog("Magic token generated [%s]", emailHash)
	return tokenStr, nil
}

func VerifyMagicToken(tokenStr string) (*jwt.Token, error) {
	key := GetSigningKey()
	if key == nil || key.PublicKey == nil {
		logging.ErrorLog("Magic token verification failed: Ed25519 key not initialized")
		return nil, errors.New("Ed25519 key not initialized")
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Enforce that we only accept EdDSA signed tokens
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			// Log at debug level for security attempts (could be noisy in production)
			logging.DebugLog("Token verification failed: unexpected signing method %T", token.Method)
			return nil, errors.New("unexpected signing method")
		}
		return key.PublicKey, nil
	})

	if err != nil {
		// Only log token parsing errors at debug level to reduce noise
		logging.DebugLog("Token verification failed: %v", err)
		return nil, err
	}

	// Optional: Log successful verifications only in debug mode
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if sub, exists := claims["sub"].(string); exists {
			emailHash := utils.HashEmail(sub)
			logging.DebugLog("Token verified [%s]", emailHash)
		}
	}

	return token, nil
}
