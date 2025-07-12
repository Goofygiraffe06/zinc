package api_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Goofygiraffe06/zinc/api"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
)

func makeRegisterRequest(t *testing.T, handler http.HandlerFunc, payload models.RegisterCompleteRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestRegisterHandler(t *testing.T) {
	userStore, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("store init error: %v", err)
	}
	defer userStore.Close()

	nonceStore := ephemeral.NewNonceStore()
	handler := api.RegisterHandler(userStore, nonceStore)

	email := "test@example.com"
	username := "testuser"
	nonce := "secure-nonce"

	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	sigB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(nonce)))

	t.Run("valid registration", func(t *testing.T) {
		nonceStore.Set(email, nonce, time.Minute)
		payload := models.RegisterCompleteRequest{Email: email, Username: username, PublicKey: pubB64, Nonce: nonce, Signature: sigB64}
		rr := makeRegisterRequest(t, handler, payload)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("invalid base64 publicKey", func(t *testing.T) {
		nonceStore.Set("b64@fail.com", nonce, time.Minute)
		payload := models.RegisterCompleteRequest{Email: "b64@fail.com", Username: "bad", PublicKey: "!!notb64", Nonce: nonce, Signature: sigB64}
		rr := makeRegisterRequest(t, handler, payload)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for bad base64 pubkey, got %d", rr.Code)
		}
	})

	t.Run("invalid base64 signature", func(t *testing.T) {
		nonceStore.Set("bad@sig.com", nonce, time.Minute)
		payload := models.RegisterCompleteRequest{Email: "bad@sig.com", Username: "bad", PublicKey: pubB64, Nonce: nonce, Signature: "!!!invalid"}
		rr := makeRegisterRequest(t, handler, payload)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for bad base64 signature, got %d", rr.Code)
		}
	})

	t.Run("signature mismatch", func(t *testing.T) {
		_, otherPriv, _ := ed25519.GenerateKey(nil)
		wrongSig := base64.StdEncoding.EncodeToString(ed25519.Sign(otherPriv, []byte(nonce)))
		nonceStore.Set("wrong@sig.com", nonce, time.Minute)
		payload := models.RegisterCompleteRequest{Email: "wrong@sig.com", Username: "sigfail", PublicKey: pubB64, Nonce: nonce, Signature: wrongSig}
		rr := makeRegisterRequest(t, handler, payload)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for invalid signature, got %d", rr.Code)
		}
	})

	t.Run("missing fields", func(t *testing.T) {
		payload := models.RegisterCompleteRequest{}
		rr := makeRegisterRequest(t, handler, payload)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing fields, got %d", rr.Code)
		}
	})

	t.Run("nonce expired or missing", func(t *testing.T) {
		payload := models.RegisterCompleteRequest{
			Email:     "missing@nonce.com",
			Username:  "ghost",
			PublicKey: pubB64,
			Nonce:     "expired-nonce",
			Signature: sigB64,
		}
		rr := makeRegisterRequest(t, handler, payload)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for missing/expired nonce, got %d", rr.Code)
		}
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		nonceStore.Set("mismatch@nonce.com", "expected-nonce", time.Minute)
		payload := models.RegisterCompleteRequest{
			Email:     "mismatch@nonce.com",
			Username:  "fail",
			PublicKey: pubB64,
			Nonce:     nonce,
			Signature: sigB64,
		}
		rr := makeRegisterRequest(t, handler, payload)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for nonce mismatch, got %d", rr.Code)
		}
	})

	t.Run("duplicate user", func(t *testing.T) {
		nonceStore.Set(email, nonce, time.Minute)
		payload := models.RegisterCompleteRequest{
			Email:     email,
			Username:  username,
			PublicKey: pubB64,
			Nonce:     nonce,
			Signature: sigB64,
		}
		rr := makeRegisterRequest(t, handler, payload)
		if rr.Code != http.StatusConflict {
			t.Errorf("expected 409 for duplicate user, got %d", rr.Code)
		}
	})
}
