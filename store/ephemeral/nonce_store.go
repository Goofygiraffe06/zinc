package ephemeral

import (
	"time"

	"github.com/Goofygiraffe06/zinc/internal/logging"
)

type NonceStore struct {
	core *coreStore
}

func NewNonceStore() *NonceStore {
	start := time.Now()
	logging.DebugLog("Nonce store creation started")

	store := &NonceStore{core: newCoreStore()}

	duration := time.Since(start)
	logging.InfoLog("Nonce store creation completed %v", duration)
	return store
}

func (s *NonceStore) Set(email, nonce string, ttl time.Duration) error {
	start := time.Now()
	logging.DebugLog("Nonce store set operation started")

	err := s.core.set(email, nonce, ttl)

	duration := time.Since(start)
	if err != nil {
		logging.WarnLog("Nonce store set operation failed: %v %v", err, duration)
	} else {
		logging.InfoLog("Nonce store set operation completed %v", duration)
	}

	return err
}

func (s *NonceStore) Get(email string) (string, bool) {
	start := time.Now()
	logging.DebugLog("Nonce store get operation started")

	nonce, found := s.core.get(email)

	duration := time.Since(start)
	if found {
		logging.InfoLog("Nonce store get operation: found %v", duration)
	} else {
		logging.DebugLog("Nonce store get operation: not found %v", duration)
	}

	return nonce, found
}

func (s *NonceStore) Delete(email string) {
	start := time.Now()
	logging.DebugLog("Nonce store delete operation started")

	s.core.delete(email)

	duration := time.Since(start)
	logging.InfoLog("Nonce store delete operation completed %v", duration)
}
