package ephemeral

import (
	"time"

	"github.com/Goofygiraffe06/zinc/internal/logging"
)

type TTLStore struct {
	core *coreStore
}

func NewTTLStore() *TTLStore {
	start := time.Now()
	logging.DebugLog("TTL store creation started")

	store := &TTLStore{core: newCoreStore()}

	duration := time.Since(start)
	logging.InfoLog("TTL store creation completed %v", duration)
	return store
}

func (s *TTLStore) Set(email string, ttl time.Duration) error {
	start := time.Now()
	logging.DebugLog("TTL store set operation started")

	err := s.core.set(email, "", ttl)

	duration := time.Since(start)
	if err != nil {
		logging.WarnLog("TTL store set operation failed: %v %v", err, duration)
	} else {
		logging.InfoLog("TTL store set operation completed %v", duration)
	}

	return err
}

func (s *TTLStore) Exists(email string) bool {
	start := time.Now()
	logging.DebugLog("TTL store exists operation started")

	_, exists := s.core.get(email)

	duration := time.Since(start)
	if exists {
		logging.DebugLog("TTL store exists operation: found %v", duration)
	} else {
		logging.DebugLog("TTL store exists operation: not found %v", duration)
	}

	return exists
}

func (s *TTLStore) Delete(email string) {
	start := time.Now()
	logging.DebugLog("TTL store delete operation started")

	s.core.delete(email)

	duration := time.Since(start)
	logging.InfoLog("TTL store delete operation completed %v", duration)
}
