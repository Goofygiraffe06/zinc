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

func (s *TTLStore) Set(email string, ttl time.Duration) error {
	err := s.core.set(email, "", ttl)
	if err != nil {
		logging.DebugLog("TTL store set failed: %v", err)
	}
	return err
}

func (s *TTLStore) Exists(email string) bool {
	_, exists := s.core.get(email)
	return exists
}

func (s *TTLStore) Delete(email string) {
	s.core.delete(email)
}
