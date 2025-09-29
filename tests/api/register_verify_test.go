package api_test

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Goofygiraffe06/zinc/api"
	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/config"
	"github.com/Goofygiraffe06/zinc/internal/manager"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
	"github.com/golang-jwt/jwt/v5"
)

var testSigningKey ed25519.PrivateKey

func TestMain(m *testing.M) {
	auth.InitSigningKey()
	testSigningKey = auth.GetSigningKey().PrivateKey
	m.Run()
}

func signToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	signed, err := token.SignedString(testSigningKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

func makeVerifyRequest(t *testing.T, handler http.HandlerFunc, token string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/register/verify?token="+url.QueryEscape(token), nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestRegisterVerifyHandler(t *testing.T) {
	ttlStore := ephemeral.NewTTLStore()
	nonceStore := ephemeral.NewNonceStore()
	handler := api.RegisterVerifyHandler(ttlStore, nonceStore, manager.NewWorkManager())

	t.Run("missing token in query", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/register/verify", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("malformed token", func(t *testing.T) {
		rr := makeVerifyRequest(t, handler, "not-a-token")
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for invalid token, got %d", rr.Code)
		}
	})

	t.Run("token signed with wrong algorithm", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "wrongalg@example.com",
			"exp": time.Now().Add(time.Minute).Unix(),
			"iss": config.JWTVerificationIssuer(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, _ := token.SignedString([]byte("dummy-secret"))

		rr := makeVerifyRequest(t, handler, signed)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for wrong algorithm, got %d", rr.Code)
		}
	})

	t.Run("token with missing subject claim", func(t *testing.T) {
		claims := jwt.MapClaims{
			"exp": time.Now().Add(time.Minute).Unix(),
			"iss": config.JWTVerificationIssuer(),
		}
		signed := signToken(t, claims)

		rr := makeVerifyRequest(t, handler, signed)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for missing subject, got %d", rr.Code)
		}
	})

	t.Run("token expired or already used", func(t *testing.T) {
		email := "expired@example.com"
		claims := jwt.MapClaims{
			"sub": email,
			"exp": time.Now().Add(time.Minute).Unix(),
			"iss": config.JWTVerificationIssuer(),
		}
		signed := signToken(t, claims)

		// No ttlStore.Set() call = simulate expired
		rr := makeVerifyRequest(t, handler, signed)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for expired token, got %d", rr.Code)
		}
	})

	t.Run("valid token should return nonce", func(t *testing.T) {
		email := "carol@example.com"
		claims := jwt.MapClaims{
			"sub": email,
			"exp": time.Now().Add(time.Minute).Unix(),
			"iss": config.JWTVerificationIssuer(),
		}
		signed := signToken(t, claims)

		ttlStore.Set(email, time.Minute)

		rr := makeVerifyRequest(t, handler, signed)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}

		// Check nonce was set
		nonce, ok := nonceStore.Get(email)
		if !ok || strings.TrimSpace(nonce) == "" {
			t.Error("expected nonce to be stored")
		}

		// Check that the TTL entry was deleted
		if ttlStore.Exists(email) {
			t.Error("expected TTL entry to be deleted after verification")
		}
	})
}
