package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/logging"
)

type SigningKey struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

var (
	signingKey *SigningKey
	once       sync.Once
)

func InitSigningKey() {
	once.Do(func() {
		start := time.Now()
		logging.DebugLog("Ed25519 key generation started")

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			logging.ErrorLog("Ed25519 key generation failed: %v", err)
			panic("failed to generate Ed25519 key: " + err.Error())
		}

		signingKey = &SigningKey{
			PrivateKey: priv,
			PublicKey:  pub,
		}

		duration := time.Since(start)
		logging.InfoLog("Ed25519 key generation success %v", duration)
	})
}

func GetSigningKey() *SigningKey {
	if signingKey == nil {
		logging.WarnLog("Signing key accessed before initialization")
	}
	return signingKey
}
