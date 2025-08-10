package utils

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashEmail creates a consistent hash for logging without exposing PII
func HashEmail(email string) string {
	hash := sha256.Sum256([]byte(email))
	return hex.EncodeToString(hash[:])[:12]
}

// hashUsername creates a consistent hash for username logging
func HashUsername(username string) string {
	hash := sha256.Sum256([]byte(username))
	return hex.EncodeToString(hash[:])[:8]
}
