package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Goofygiraffe06/zinc/api"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/store"
)

func setup(t *testing.T) (*store.SQLiteStore, *store.EphemeralStore, func()) {
	t.Helper()

	userStore, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create SQLite store: %v", err)
	}

	ephemeral := store.NewEphemeralStore()

	cleanup := func() {
		userStore.Close()
	}
	return userStore, ephemeral, cleanup
}

func makeRequest(t *testing.T, handler http.HandlerFunc, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/register/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestRegisterInitHandler(t *testing.T) {
	// Set required environment variables
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("JWT_ISSUER", "zinc-test")
	os.Setenv("JWT_EXPIRES_IN", "1") // in minutes

	t.Run("valid registration", func(t *testing.T) {
		store, ephemeral, cleanup := setup(t)
		defer cleanup()

		handler := api.RegisterInitHandler(store, ephemeral)
		rr := makeRequest(t, handler, map[string]string{"email": "test@example.com"})

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}

		if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		var res map[string]string
		if err := json.NewDecoder(rr.Body).Decode(&res); err != nil {
			t.Fatalf("response not valid JSON: %v", err)
		}
		if res["token"] == "" {
			t.Errorf(`expected non-empty token in response, got %v`, res)
		}
	})

	t.Run("missing email field", func(t *testing.T) {
		store, ephemeral, cleanup := setup(t)
		defer cleanup()

		handler := api.RegisterInitHandler(store, ephemeral)
		rr := makeRequest(t, handler, map[string]string{})

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request, got %d", rr.Code)
		}
	})

	t.Run("empty email string", func(t *testing.T) {
		store, ephemeral, cleanup := setup(t)
		defer cleanup()

		handler := api.RegisterInitHandler(store, ephemeral)
		rr := makeRequest(t, handler, map[string]string{"email": ""})

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for empty email, got %d", rr.Code)
		}
	})

	t.Run("user already exists", func(t *testing.T) {
		store, ephemeral, cleanup := setup(t)
		defer cleanup()

		_ = store.AddUser(models.User{
			Email:     "bob@example.com",
			Username:  "bob",
			PublicKey: "bobkey",
		})

		handler := api.RegisterInitHandler(store, ephemeral)
		rr := makeRequest(t, handler, map[string]string{"email": "bob@example.com"})

		if rr.Code != http.StatusConflict {
			t.Errorf("expected 409 Conflict for existing user, got %d", rr.Code)
		}
	})

	t.Run("malformed JSON body", func(t *testing.T) {
		store, ephemeral, cleanup := setup(t)
		defer cleanup()

		handler := api.RegisterInitHandler(store, ephemeral)
		req := httptest.NewRequest(http.MethodPost, "/register/init", bytes.NewBufferString(`not-json`))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for invalid JSON, got %d", rr.Code)
		}
	})
}
