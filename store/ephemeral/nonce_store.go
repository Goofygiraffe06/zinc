package ephemeral

import (
	"time"

	"github.com/Goofygiraffe06/zinc/internal/logging"
)

type NonceStore struct {
	core *coreStore
}

func NewNonceStore() *NonceStore {
	store := &NonceStore{core: newCoreStore()}
	logging.DebugLog("Nonce store created")
	return store
}

func (s *NonceStore) Set(email, nonce string, ttl time.Duration) error {
	err := s.core.set(email, nonce, ttl)
	if err != nil {
		logging.DebugLog("Nonce store set failed: %v", err)
	}
	return err
}

func (s *NonceStore) Get(email string) (string, bool) {
	nonce, found := s.core.get(email)
	return nonce, found
}

func (s *NonceStore) Delete(email string) {
	s.core.delete(email)
}

// DeleteIfExists atomically checks existence and deletes the key if it exists.
// Returns true if the key existed and was deleted, false otherwise.
func (s *TTLStore) DeleteIfExists(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[key]; !exists {
		return false
	}
	delete(s.data, key)
	return true
}
