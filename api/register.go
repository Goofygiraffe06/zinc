package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/manager"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/internal/utils"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
)

func RegisterHandler(userStore *store.SQLiteStore, nonceStore *ephemeral.NonceStore, mgr *manager.WorkManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		var req models.RegisterCompleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logging.WarnLog("Registration complete failed: invalid JSON")
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Invalid JSON"})
			return
		}

		// Sanitize input
		req.Email = strings.TrimSpace(req.Email)
		req.Username = strings.TrimSpace(req.Username)
		req.PublicKey = strings.TrimSpace(req.PublicKey)
		req.Signature = strings.TrimSpace(req.Signature)
		req.Nonce = strings.TrimSpace(req.Nonce)
		req.Username = strings.ToLower(req.Username)
		req.Username = strings.ReplaceAll(req.Username, " ", "")
		req.PublicKey = strings.ReplaceAll(req.PublicKey, "\n", "")
		req.PublicKey = strings.ReplaceAll(req.PublicKey, "\r", "")

		emailHash := utils.HashEmail(req.Email)
		usernameHash := utils.HashUsername(req.Username)

		// Validate payload
		if err := validate.Struct(req); err != nil {
			logging.WarnLog("Registration complete failed: validation error [%s][%s]", emailHash, usernameHash)
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Validation failed"})
			return
		}

		// Check for existing user
		if userStore.Exists(req.Email) {
			logging.WarnLog("Registration complete failed: user exists [%s]", emailHash)
			respondJSON(w, http.StatusConflict, models.ErrorResponse{Error: "User already registered"})
			return
		}

		// Validate nonce
		storedNonce, exists := nonceStore.Get(req.Email)
		if !exists || storedNonce != req.Nonce {
			logging.WarnLog("Registration complete failed: nonce invalid [%s]", emailHash)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Nonce missing, expired, or does not match"})
			return
		}

		// Verify signature (offload to crypto pool)
		sigStart := time.Now()
		var (
			valid bool
			verr  error
		)
		done := make(chan struct{})
		_ = mgr.SubmitCrypto(func(ctx context.Context) {
			defer close(done)
			// Bound the verification time per request
			authCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			// Use a small goroutine to respect authCtx even if VerifySignature is CPU-bound
			resultCh := make(chan struct{})
			go func() {
				valid, verr = auth.VerifySignature(req.PublicKey, req.Nonce, req.Signature)
				close(resultCh)
			}()
			select {
			case <-authCtx.Done():
				verr = authCtx.Err()
			case <-resultCh:
			}
		})
		select {
		case <-done:
		case <-time.After(6 * time.Second): // hard cap
			verr = context.DeadlineExceeded
		}
		sigDuration := time.Since(sigStart)

		if verr != nil {
			logging.ErrorLog("Registration complete failed: signature error [%s]: %v", emailHash, verr)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid signature"})
			return
		}

		if !valid {
			logging.WarnLog("Registration complete failed: invalid signature [%s]", emailHash)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid signature"})
			return
		}

		// Create user (offload to DB pool)
		dbStart := time.Now()
		var dbErr error
		dbDone := make(chan struct{})
		_ = mgr.SubmitDB(func(ctx context.Context) {
			defer close(dbDone)
			// Tight bound to avoid blocking HTTP goroutine
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			// Since sqlite calls are blocking, we run Exec in a goroutine and wait.
			resultCh := make(chan error, 1)
			go func() {
				resultCh <- userStore.AddUser(models.User{
					Email:     req.Email,
					Username:  req.Username,
					PublicKey: req.PublicKey,
				})
			}()
			select {
			case <-ctx.Done():
				dbErr = ctx.Err()
			case dbErr = <-resultCh:
			}
		})
		select {
		case <-dbDone:
		case <-time.After(4 * time.Second):
			dbErr = context.DeadlineExceeded
		}
		dbDuration := time.Since(dbStart)

		// On DB error, report and exit
		if dbErr != nil {
			logging.ErrorLog("Registration complete failed: database error [%s][%s]: %v", emailHash, usernameHash, dbErr)
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to save user"})
			return
		}

		// Clean up nonce
		nonceStore.Delete(req.Email)

		duration := time.Since(start)
		logging.InfoLog("Registration complete success [%s][%s] %v (db: %v, sig: %v)",
			emailHash, usernameHash, duration, dbDuration, sigDuration)
		respondJSON(w, http.StatusOK, models.StatusResponse{Status: "ok"})
	}
}
