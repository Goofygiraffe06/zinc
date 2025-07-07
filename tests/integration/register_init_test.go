package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

var baseURL = getBaseURL()

func getBaseURL() string {
	if url := os.Getenv("ZINC_BASE_URL"); url != "" {
		return url
	}
	return "http://localhost:8000"
}

// TestMain performs a health check before executing any tests
func TestMain(m *testing.M) {
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		println("ZINC server is not reachable at", baseURL)
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		println("/health check failed with status:", resp.Status)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestRegisterInitEndpoint(t *testing.T) {
	testCases := []struct {
		name           string
		body           map[string]string
		contentType    string
		expectedStatus int
	}{
		{
			name:           "valid email",
			body:           map[string]string{"email": "inituser1@example.com"},
			contentType:    "application/json",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing content-type header",
			body:           map[string]string{"email": "inituser2@example.com"},
			contentType:    "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "empty email",
			body:           map[string]string{"email": ""},
			contentType:    "application/json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid field",
			body:           map[string]string{"foo": "bar"},
			contentType:    "application/json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "duplicate email reuse",
			body:           map[string]string{"email": "inituser1@example.com"},
			contentType:    "application/json",
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "whitespace email",
			body:           map[string]string{"email": "   "},
			contentType:    "application/json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "capitalized email",
			body:           map[string]string{"email": "InitUser3@Example.Com"},
			contentType:    "application/json",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("Failed to marshal JSON: %v", err)
			}

			req, err := http.NewRequest("POST", baseURL+"/register/init", bytes.NewReader(payload))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("HTTP request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}
		})
	}
}
