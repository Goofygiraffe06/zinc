package auth

import (
	"time"

	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

func GenerateJWT(email string) (string, error) {
	claims := jwt.MapClaims{
		"sub": email,
		"iss": config.JWTIssuer(),
		"exp": time.Now().Add(config.JWTExpiresIn()).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.JWTSecret()))
}
