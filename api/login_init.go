package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/manager"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
)

func AuthInitHandler(userStore *store.SQLiteStore, nonceStore *ephemeral.NonceStore, mgr *manager.WorkManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.LoginInitRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Invalid JSON"})
			return
		}

		req.Email = strings.ToLower(strings.TrimSpace(req.Email))

		if err := validate.Struct(req); err != nil {
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Invalid email address"})
			return
		}

		if !userStore.Exists(req.Email) {
			// Do NOT reveal user existence
			respondJSON(w, http.StatusOK, models.LoginInitResponse{Nonce: ""})
			return
		}

		nonce, err := auth.GenerateNonce()
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to generate nonce"})
			return
		}

		if err := nonceStore.Set(req.Email, nonce, time.Minute); err != nil {
			respondJSON(w, http.StatusServiceUnavailable, models.ErrorResponse{Error: "Server busy"})
			return
		}

		respondJSON(w, http.StatusOK, models.LoginInitResponse{Nonce: nonce})
	}
}
