package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"

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
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			logging.ErrorLog("Ed25519 key generation failed: %v", err)
			panic("failed to generate Ed25519 key: " + err.Error())
		}

		signingKey = &SigningKey{
			PrivateKey: priv,
			PublicKey:  pub,
		}

		logging.DebugLog("Ed25519 key generated successfully")
	})
}

func GetSigningKey() *SigningKey {
	if signingKey == nil {
		logging.ErrorLog("Signing key accessed before initialization")
	}
	return signingKey
}
