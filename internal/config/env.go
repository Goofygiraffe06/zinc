package config

import (
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("config: no .env file found, using system environment variables")
	}
}

// MustGetEnv returns the value of the environment variable or logs a fatal error if it's not set.
func MustGetEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("config: missing required environment variable: %s", key)
	}
	return v
}

// GetEnv returns the value of the environment variable or a default if it's not set.
func GetEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// MustParseDuration retrieves a duration from env or uses fallback, logs fatally if invalid.
func MustParseDuration(key, fallback string) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		val = fallback
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		log.Fatalf("config: invalid duration in %s: %v", key, err)
	}
	return d
}
