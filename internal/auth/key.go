package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
)

type SigningKey struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

var (
	signingKey *SigningKey
	once       sync.Once
)

// Call this during app startup (main.go)
func InitSigningKey() {
	once.Do(func() {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic("failed to generate Ed25519 key: " + err.Error())
		}
		signingKey = &SigningKey{
			PrivateKey: priv,
			PublicKey:  pub,
		}
	})
}

func GetSigningKey() *SigningKey {
	return signingKey
}
