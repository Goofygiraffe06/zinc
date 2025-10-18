package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Goofygiraffe06/zinc/api"
	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/manager"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
)

// setupAuthInit is like setup but for AuthInitHandler tests
func setupAuthInit(t *testing.T) (*store.SQLiteStore, *ephemeral.NonceStore, func()) {
	t.Helper()

	userStore, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create SQLite store: %v", err)
	}

	nonceStore := ephemeral.NewNonceStore()

	cleanup := func() {
		userStore.Close()
	}

	return userStore, nonceStore, cleanup
}

func makeAuthInitRequest(t *testing.T, handler http.HandlerFunc, payload any) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	return rr
}

func TestAuthInitHandler(t *testing.T) {
	auth.InitSigningKey()

	t.Run("existing user returns nonce", func(t *testing.T) {
		userStore, nonceStore, cleanup := setupAuthInit(t)
		defer cleanup()

		// Add a user to the DB
		err := userStore.AddUser(models.User{
			Email:     "alice@example.com",
			Username:  "alice",
			PublicKey: "alicepubkey",
		})
		if err != nil {
			t.Fatalf("failed to add user: %v", err)
		}

		handler := api.AuthInitHandler(userStore, nonceStore, manager.NewWorkManager())
		rr := makeAuthInitRequest(t, handler, map[string]string{"email": "alice@example.com"})

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}

		var res models.LoginInitResponse
		if err := json.NewDecoder(rr.Body).Decode(&res); err != nil {
			t.Fatalf("response not valid JSON: %v", err)
		}
		if res.Nonce == "" {
			t.Errorf("expected non-empty nonce for existing user, got %q", res.Nonce)
		}
	})

	t.Run("non-existing user returns empty nonce", func(t *testing.T) {
		userStore, nonceStore, cleanup := setupAuthInit(t)
		defer cleanup()

		handler := api.AuthInitHandler(userStore, nonceStore, manager.NewWorkManager())
		rr := makeAuthInitRequest(t, handler, map[string]string{"email": "nobody@example.com"})

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}

		var res models.LoginInitResponse
		if err := json.NewDecoder(rr.Body).Decode(&res); err != nil {
			t.Fatalf("invalid JSON response: %v", err)
		}
		if res.Nonce != "" {
			t.Errorf("expected empty nonce for non-existent user, got %q", res.Nonce)
		}
	})

	t.Run("missing email field", func(t *testing.T) {
		userStore, nonceStore, cleanup := setupAuthInit(t)
		defer cleanup()

		handler := api.AuthInitHandler(userStore, nonceStore, manager.NewWorkManager())
		rr := makeAuthInitRequest(t, handler, map[string]string{})

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request, got %d", rr.Code)
		}
	})

	t.Run("empty email string", func(t *testing.T) {
		userStore, nonceStore, cleanup := setupAuthInit(t)
		defer cleanup()

		handler := api.AuthInitHandler(userStore, nonceStore, manager.NewWorkManager())
		rr := makeAuthInitRequest(t, handler, map[string]string{"email": ""})

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for empty email, got %d", rr.Code)
		}
	})

	t.Run("malformed JSON body", func(t *testing.T) {
		userStore, nonceStore, cleanup := setupAuthInit(t)
		defer cleanup()

		handler := api.AuthInitHandler(userStore, nonceStore, manager.NewWorkManager())
		req := httptest.NewRequest(http.MethodPost, "/auth/init", bytes.NewBufferString(`not-json`))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request, got %d", rr.Code)
		}
	})
}
