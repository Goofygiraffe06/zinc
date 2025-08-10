package ephemeral

import (
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/logging"
	"github.com/Goofygiraffe06/zinc/internal/utils"
)

var (
	ErrTooLong   = errors.New("key too long")
	ErrStoreFull = errors.New("ephemeral store full")
	maxKeyLength = 255
	maxStoreSize = 1000
)

type item struct {
	value     string
	expiresAt time.Time
}

type coreStore struct {
	data map[string]*item
	mu   sync.RWMutex
}

func newCoreStore() *coreStore {
	store := &coreStore{
		data: make(map[string]*item),
	}

	go store.cleanup()

	logging.DebugLog("Ephemeral store initialized")
	return store
}

func (s *coreStore) set(key, value string, ttl time.Duration) error {
	if len(key) > maxKeyLength {
		keyHash := utils.HashEmail(key)
		logging.DebugLog("Store set failed: key too long [%s] (length: %d)", keyHash, len(key))
		return ErrTooLong
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.data) >= maxStoreSize {
		logging.WarnLog("Store set failed: store full (size: %d)", len(s.data))
		return ErrStoreFull
	}

	s.data[key] = &item{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}

	keyHash := utils.HashEmail(key)
	logging.DebugLog("Store set success [%s] ttl=%v", keyHash, ttl)
	return nil
}

func (s *coreStore) get(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	it, ok := s.data[key]
	if !ok {
		return "", false
	}

	if time.Now().After(it.expiresAt) {
		return "", false
	}

	keyHash := utils.HashEmail(key)
	logging.DebugLog("Store get success [%s]", keyHash)
	return it.value, true
}

// ConstantTimeEquals compares two strings in constant time to prevent timing attacks.
func ConstantTimeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	result := subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1

	if !result {
		logging.DebugLog("Constant time comparison failed")
	}

	return result
}

func (s *coreStore) delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, existed := s.data[key]
	delete(s.data, key)

	if existed {
		keyHash := utils.HashEmail(key)
		logging.DebugLog("Store delete success [%s]", keyHash)
	}
}

func (s *coreStore) cleanup() {
	logging.DebugLog("Store cleanup goroutine started")
	ticker := time.NewTicker(1 * time.Minute)

	for range ticker.C {
		now := time.Now()
		s.mu.Lock()

		expiredCount := 0
		for k, v := range s.data {
			if now.After(v.expiresAt) {
				delete(s.data, k)
				expiredCount++
			}
		}

		currentSize := len(s.data)
		s.mu.Unlock()

		if expiredCount > 0 {
			logging.InfoLog("Store cleanup: removed %d expired items (current size: %d)", expiredCount, currentSize)
		}
	}
}
