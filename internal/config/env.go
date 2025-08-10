package config

import (
	"os"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/joho/godotenv"
)

func init() {
	start := time.Now()
	logging.DebugLog("Environment configuration loading started")

	if err := godotenv.Load(); err != nil {
		logging.WarnLog("Environment configuration: no .env file found, using system environment variables")
	} else {
		logging.InfoLog("Environment configuration: .env file loaded successfully")
	}

	duration := time.Since(start)
	logging.InfoLog("Environment configuration loading completed %v", duration)
}

// MustGetEnv returns the value of the environment variable or logs a fatal error if it's not set.
func MustGetEnv(key string) string {
	logging.DebugLog("Environment variable lookup: %s", key)

	v := os.Getenv(key)
	if v == "" {
		logging.ErrorLog("Environment configuration failed: missing required variable %s", key)
		// Using panic instead of log.Fatalf to be consistent with other fatal errors in your codebase
		panic("config: missing required environment variable: " + key)
	}

	logging.DebugLog("Environment variable found: %s", key)
	return v
}

// GetEnv returns the value of the environment variable or a default if it's not set.
func GetEnv(key, fallback string) string {
	logging.DebugLog("Environment variable lookup with fallback: %s", key)

	if val := os.Getenv(key); val != "" {
		logging.DebugLog("Environment variable found: %s", key)
		return val
	}

	logging.DebugLog("Environment variable not found, using fallback: %s", key)
	return fallback
}

// MustParseDuration retrieves a duration from env or uses fallback, logs fatally if invalid.
func MustParseDuration(key, fallback string) time.Duration {
	start := time.Now()
	logging.DebugLog("Duration parsing started: %s", key)

	val := os.Getenv(key)
	if val == "" {
		val = fallback
		logging.DebugLog("Duration parsing using fallback: %s = %s", key, fallback)
	} else {
		logging.DebugLog("Duration parsing using env value: %s = %s", key, val)
	}

	d, err := time.ParseDuration(val)
	if err != nil {
		logging.ErrorLog("Duration parsing failed: %s = %s, error: %v", key, val, err)
		// Using panic instead of log.Fatalf to be consistent with other fatal errors
		panic("config: invalid duration in " + key + ": " + err.Error())
	}

	duration := time.Since(start)
	logging.InfoLog("Duration parsing success: %s = %v (%v)", key, d, duration)
	return d
}
