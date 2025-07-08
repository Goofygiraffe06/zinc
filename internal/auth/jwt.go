package auth

import (
	"time"

	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

func GenerateMagicToken(email string) (string, error) {
	claims := jwt.MapClaims{
		"sub": email,
		"iss": config.JWTVerificationIssuer(),
		"exp": time.Now().Add(config.JWTRegistrationExpiresIn()).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.JWTSecret()))
}
