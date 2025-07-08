package auth

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateNonce returns a 32-byte hex-encoded nonce
func GenerateNonce() (string, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}
