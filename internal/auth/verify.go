package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

func VerifySignature(pubKeyB64, message, signatureB64 string) (bool, error) {
	// Decode base64 public key
	pubKey, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return false, errors.New("invalid base64 public key")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return false, errors.New("incorrect public key size")
	}

	// Decode base64 signature
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, errors.New("invalid base64 signature")
	}
	if len(sig) != ed25519.SignatureSize {
		return false, errors.New("incorrect signature size")
	}

	// Verify signature
	valid := ed25519.Verify(pubKey, []byte(message), sig)
	return valid, nil
}
