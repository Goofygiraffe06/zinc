package config

import "time"

func JWTSecret() string {
	return MustGetEnv("JWT_SECRET")
}

func JWTIssuer() string {
	return GetEnv("JWT_ISSUER", "zinc-auth")
}

func JWTExpiresIn() time.Duration {
	return MustParseDuration("JWT_EXPIRES_IN", "15m")
}
