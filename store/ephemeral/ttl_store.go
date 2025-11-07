package ephemeral

import (
	"time"

	"github.com/Goofygiraffe06/zinc/internal/logging"
)

type TTLStore struct {
	core *coreStore
}

func NewTTLStore() *TTLStore {
	store := &TTLStore{core: newCoreStore()}
	logging.DebugLog("TTL store created")
	return store
}

// Set stores a key with optional value and TTL. If value is empty, only the key is stored.
func (s *TTLStore) Set(key string, ttl time.Duration) error {
	err := s.core.set(key, "", ttl)
	if err != nil {
		logging.DebugLog("TTL store set failed: %v", err)
	}
	return err
}

// SetWithValue stores a key-value pair with TTL (for nonce->email mapping)
func (s *TTLStore) SetWithValue(key, value string, ttl time.Duration) error {
	err := s.core.set(key, value, ttl)
	if err != nil {
		logging.DebugLog("TTL store set with value failed: %v", err)
	}
	return err
}

func (s *TTLStore) Exists(key string) bool {
	_, exists := s.core.get(key)
	return exists
}

// Get retrieves the value associated with a key. Returns empty string if not found or expired.
func (s *TTLStore) Get(key string) (string, bool) {
	return s.core.get(key)
}

func (s *TTLStore) Delete(key string) {
	s.core.delete(key)
}
