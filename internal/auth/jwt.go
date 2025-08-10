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
	start := time.Now()
	emailHash := utils.HashEmail(email)
	logging.DebugLog("Magic token generation started [%s]", emailHash)

	key := GetSigningKey()
	if key == nil || key.PrivateKey == nil {
		logging.ErrorLog("Magic token generation failed [%s]: Ed25519 key not initialized", emailHash)
		return "", errors.New("Ed25519 key not initialized")
	}

	claims := jwt.MapClaims{
		"sub": email,
		"iss": config.JWTVerificationIssuer(),
		"exp": time.Now().Add(config.JWTRegistrationExpiresIn()).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenStr, err := token.SignedString(key.PrivateKey)
	if err != nil {
		logging.ErrorLog("Magic token signing failed [%s]: %v", emailHash, err)
		return "", err
	}

	duration := time.Since(start)
	logging.InfoLog("Magic token generation success [%s] %v", emailHash, duration)
	return tokenStr, nil
}

func VerifyMagicToken(tokenStr string) (*jwt.Token, error) {
	start := time.Now()
	logging.DebugLog("Magic token verification started")

	key := GetSigningKey()
	if key == nil || key.PublicKey == nil {
		logging.ErrorLog("Magic token verification failed: Ed25519 key not initialized")
		return nil, errors.New("Ed25519 key not initialized")
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Enforce that we only accept EdDSA signed tokens
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			logging.WarnLog("Magic token verification failed: unexpected signing method %T", token.Method)
			return nil, errors.New("unexpected signing method")
		}
		return key.PublicKey, nil
	})

	if err != nil {
		logging.WarnLog("Magic token verification failed: %v", err)
		return nil, err
	}

	// Extract email from token for logging (if available)
	var emailHash string
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if sub, exists := claims["sub"].(string); exists {
			emailHash = utils.HashEmail(sub)
		}
	}

	if emailHash != "" {
		duration := time.Since(start)
		logging.InfoLog("Magic token verification success [%s] %v", emailHash, duration)
	} else {
		duration := time.Since(start)
		logging.InfoLog("Magic token verification success %v", duration)
	}

	return token, nil
}
