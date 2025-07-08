package config

import "time"

func JWTSecret() string {
	return MustGetEnv("JWT_SECRET")
}

func JWTVerificationIssuer() string {
	return GetEnv("JWT_VERIFICATION_ISSUER", "zinc-verify")
}

func JWTIssuer() string {
	return GetEnv("JWT_ISSUER", "zinc-auth")
}

func JWTRegistrationExpiresIn() time.Duration {
	return MustParseDuration("JWT_REGISTRATION_EXPIRES_IN", "3m")
}

func JWTSessionExpiresIn() time.Duration {
	return MustParseDuration("JWT_SESSION_EXPIRES_IN", "6h")
}
