package controller

import (
	"sync"

	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/utils"
)

type VerificationRegistry struct {
	mu       sync.RWMutex
	channels map[string]chan struct{}
}

func NewVerificationRegistry() *VerificationRegistry {
	return &VerificationRegistry{
		channels: make(map[string]chan struct{}),
	}
}

func (vr *VerificationRegistry) Register(nonce string) chan struct{} {
	vr.mu.Lock()
	defer vr.mu.Unlock()

	ch := make(chan struct{}, 1) // buffered to prevent SMTP blocking if handler already exited
	vr.channels[nonce] = ch

	nonceHash := utils.HashEmail(nonce)
	logging.DebugLog("Interrupt: registered wait channel for nonce [%s]", nonceHash)

	return ch
}

func (vr *VerificationRegistry) Notify(nonce string) {
	vr.mu.RLock()
	ch, exists := vr.channels[nonce]
	vr.mu.RUnlock()

	if !exists {
		nonceHash := utils.HashEmail(nonce)
		logging.DebugLog("Interrupt: notify called but no handler waiting [%s]", nonceHash)
		return
	}

	nonceHash := utils.HashEmail(nonce)
	logging.DebugLog("Interrupt: firing notification for nonce [%s]", nonceHash)

	// Non-blocking send - if channel already closed or handler already received, this is safe
	select {
	case ch <- struct{}{}:
		logging.DebugLog("Interrupt: notification sent for nonce [%s]", nonceHash)
	default:
		logging.DebugLog("Interrupt: notification channel full or closed for nonce [%s]", nonceHash)
	}
}

func (vr *VerificationRegistry) Delete(nonce string) {
	vr.mu.Lock()
	defer vr.mu.Unlock()

	ch, exists := vr.channels[nonce]
	if !exists {
		return
	}

	// Close the channel to unblock any waiting goroutines
	close(ch)
	delete(vr.channels, nonce)

	nonceHash := utils.HashEmail(nonce)
	logging.DebugLog("Interrupt: cleaned up channel for nonce [%s]", nonceHash)
}

// Count returns the current number of registered wait channels.
func (vr *VerificationRegistry) Count() int {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	return len(vr.channels)
}
