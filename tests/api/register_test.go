package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Goofygiraffe06/zinc/api"
	"github.com/Goofygiraffe06/zinc/internal/controller"
	"github.com/Goofygiraffe06/zinc/internal/manager"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
)

func TestRegisterHandler_Timeout(t *testing.T) {
	userStore, _ := store.NewSQLiteStore(":memory:")
	defer userStore.Close()

	ttlStore := ephemeral.NewTTLStore()
	registry := controller.NewVerificationRegistry()
	mgr := manager.NewWorkManager()
	defer mgr.Close()

	handler := api.RegisterHandler(userStore, ttlStore, registry, mgr)

	email := "timeout@example.com"
	username := "timeoutuser"
	nonce := "test-nonce"

	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	sigB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(nonce)))

	payload := models.RegisterCompleteRequest{
		Email:     email,
		Username:  username,
		PublicKey: pubB64,
		Nonce:     nonce,
		Signature: sigB64,
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Attach a very short deadline to force the handler to observe a timeout.
	ctx, cancel := context.WithTimeout(req.Context(), 50*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	// Do NOT notify the registry / set the nonce in ttlStore so the handler blocks until context timeout.
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestTimeout {
		t.Fatalf("expected 408 Request Timeout, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestRegisterHandler_SuccessWithInterrupt(t *testing.T) {
	userStore, _ := store.NewSQLiteStore(":memory:")
	defer userStore.Close()

	ttlStore := ephemeral.NewTTLStore()
	registry := controller.NewVerificationRegistry()
	mgr := manager.NewWorkManager()
	defer mgr.Close()

	handler := api.RegisterHandler(userStore, ttlStore, registry, mgr)

	email := "success@example.com"
	username := "successuser"
	nonce := "test-nonce-123"

	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	sigB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(nonce)))

	payload := models.RegisterCompleteRequest{
		Email:     email,
		Username:  username,
		PublicKey: pubB64,
		Nonce:     nonce,
		Signature: sigB64,
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	// Simulate SMTP verification in background
	go func() {
		time.Sleep(100 * time.Millisecond)
		ttlStore.SetWithValue(nonce, email, 3*time.Minute)
		registry.Notify(nonce)
	}()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d body=%s", rr.Code, rr.Body.String())
	}
}
