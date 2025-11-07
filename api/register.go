package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/auth"
	"github.com/Goofygiraffe06/zinc/internal/controller"
	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/manager"
	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/internal/utils"
	"github.com/Goofygiraffe06/zinc/store"
	"github.com/Goofygiraffe06/zinc/store/ephemeral"
)

func RegisterHandler(userStore *store.SQLiteStore, ttlStore *ephemeral.TTLStore, registry *controller.VerificationRegistry, mgr *manager.WorkManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		var req models.RegisterCompleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logging.WarnLog("Registration failed: invalid JSON")
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Invalid JSON"})
			return
		}

		// Sanitize input using standard pattern
		req.Email = strings.ToLower(strings.TrimSpace(req.Email))
		req.Username = strings.ToLower(strings.TrimSpace(req.Username))
		req.Username = strings.ReplaceAll(req.Username, " ", "")
		req.PublicKey = strings.ReplaceAll(req.PublicKey, "\n", "")
		req.PublicKey = strings.ReplaceAll(req.PublicKey, "\r", "")
		req.Signature = strings.TrimSpace(req.Signature)
		req.Nonce = strings.TrimSpace(req.Nonce)

		emailHash := utils.HashEmail(req.Email)
		usernameHash := utils.HashUsername(req.Username)
		nonceHash := utils.HashEmail(req.Nonce)

		// Validate payload
		if err := validate.Struct(req); err != nil {
			logging.WarnLog("Registration failed: validation error [%s][%s]", emailHash, usernameHash)
			respondJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "Validation failed"})
			return
		}

		userExists := userStore.Exists(req.Email)

		expectedEmailKey := "expected:" + req.Nonce
		if err := ttlStore.SetWithValue(expectedEmailKey, req.Email, 3*time.Minute); err != nil {
			logging.ErrorLog("Registration failed: could not store expected email [%s]: %v", emailHash, err)
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Registration initialization failed"})
			return
		}

		// Register with interrupt controller to get wait channel
		waitCh := registry.Register(req.Nonce)
		defer registry.Delete(req.Nonce)
		defer ttlStore.Delete(expectedEmailKey) // Clean up expected email on exit

		logging.DebugLog("Registration: waiting for SMTP verification [%s] nonce=[%s]", emailHash, nonceHash) // Block and wait for one of three outcomes
		select {
		case <-waitCh:
			// SMTP server has fired the interrupt - email verified
			logging.DebugLog("Registration: interrupt received [%s] nonce=[%s]", emailHash, nonceHash)

		case <-time.After(3 * time.Minute):
			// Timeout: SMTP didn't verify within 3 minutes
			logging.WarnLog("Registration timeout after 3m [%s] nonce=[%s]", emailHash, nonceHash)
			respondJSON(w, http.StatusRequestTimeout, models.ErrorResponse{Error: "Registration timeout - email verification not received"})
			return

		case <-r.Context().Done():
			// Client disconnected before SMTP verified
			logging.WarnLog("Registration cancelled by client [%s] nonce=[%s]", emailHash, nonceHash)
			respondJSON(w, http.StatusRequestTimeout, models.ErrorResponse{Error: "Request timeout"})
			return
		} // Wake up from interrupt - now verify everything

		// compare SMTP-verified email with request email
		verifiedEmail, exists := ttlStore.Get(req.Nonce)
		if !exists {
			logging.WarnLog("Registration failed: nonce expired in TTLStore [%s] nonce=[%s]", emailHash, nonceHash)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Verification expired"})
			return
		}

		// email in TTLStore must match email in request
		if verifiedEmail != req.Email {
			logging.WarnLog("Registration failed: email mismatch verified=[%s] claimed=[%s] nonce=[%s]",
				utils.HashEmail(verifiedEmail), emailHash, nonceHash)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Email verification mismatch"})
			return
		}

		// Clean up TTLStore entry (single-use proof)
		ttlStore.Delete(req.Nonce)

		// Check user existence again (could have changed during wait)
		if userExists || userStore.Exists(req.Email) {
			logging.WarnLog("Registration failed: user exists [%s]", emailHash)
			respondJSON(w, http.StatusConflict, models.ErrorResponse{Error: "User already registered"})
			return
		}

		// Verify Ed25519 signature
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
			logging.ErrorLog("Registration failed: signature error [%s]: %v", emailHash, verr)
			respondJSON(w, http.StatusForbidden, models.ErrorResponse{Error: "Invalid signature"})
			return
		}

		if !valid {
			logging.WarnLog("Registration failed: invalid signature [%s]", emailHash)
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
			logging.ErrorLog("Registration failed: database error [%s][%s]: %v", emailHash, usernameHash, dbErr)
			respondJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to save user"})
			return
		}

		duration := time.Since(start)
		logging.InfoLog("Registration completed via interrupt [%s][%s] %v (db: %v, sig: %v)",
			emailHash, usernameHash, duration, dbDuration, sigDuration)
		respondJSON(w, http.StatusOK, models.StatusResponse{Status: "ok"})
	}
}
