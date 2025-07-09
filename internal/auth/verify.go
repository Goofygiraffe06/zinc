package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

func VerifySignature(pubKeyPEM, message, signatureHex string) (bool, error) {
	// Decode PEM
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return false, errors.New("invalid PEM format or missing public key")
	}

	// Parse to ed25519.PublicKey
	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	pubKey, ok := pubKeyInterface.(ed25519.PublicKey)
	if !ok {
		return false, errors.New("not an Ed25519 public key")
	}

	// Decode signature
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, errors.New("invalid signature hex")
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return false, errors.New("invalid signature size")
	}

	ok = ed25519.Verify(pubKey, []byte(message), sigBytes)
	return ok, nil
}
