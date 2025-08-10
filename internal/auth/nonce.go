package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/logging"
)

// GenerateNonce returns a 32-byte hex-encoded nonce
func GenerateNonce() (string, error) {
	start := time.Now()
	logging.DebugLog("Nonce generation started")

	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		logging.ErrorLog("Nonce generation failed: %v", err)
		return "", err
	}

	nonceStr := hex.EncodeToString(nonce)
	duration := time.Since(start)
	logging.InfoLog("Nonce generation success %v", duration)

	return nonceStr, nil
}
