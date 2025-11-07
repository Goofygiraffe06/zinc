package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Goofygiraffe06/zinc/api"
	"github.com/Goofygiraffe06/zinc/internal/models"
)

func TestRegisterInitHandler(t *testing.T) {
	t.Run("valid nonce generation", func(t *testing.T) {
		handler := api.RegisterInitHandler()
		req := httptest.NewRequest(http.MethodPost, "/register/init", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}

		var res models.NonceResponse
		if err := json.NewDecoder(rr.Body).Decode(&res); err != nil {
			t.Fatalf("response not valid JSON: %v", err)
		}
		if res.Nonce == "" || len(res.Nonce) != 64 {
			t.Error("expected 64-char nonce")
		}
	})
}
