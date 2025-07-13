package auth

import (
	"errors"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

func GenerateMagicToken(email string) (string, error) {
	key := GetSigningKey()
	if key == nil || key.PrivateKey == nil {
		return "", errors.New("Ed25519 key not initialized")
	}

	claims := jwt.MapClaims{
		"sub": email,
		"iss": config.JWTVerificationIssuer(),
		"exp": time.Now().Add(config.JWTRegistrationExpiresIn()).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(key.PrivateKey)
}

func VerifyMagicToken(tokenStr string) (*jwt.Token, error) {
	key := GetSigningKey()
	if key == nil || key.PublicKey == nil {
		return nil, errors.New("Ed25519 key not initialized")
	}

	return jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Enforce that we only accept EdDSA signed tokens
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return key.PublicKey, nil
	})
}
