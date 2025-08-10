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
	start := time.Now()
	logging.DebugLog("Ephemeral store initialization started")

	store := &coreStore{
		data: make(map[string]*item),
	}

	go store.cleanup()

	duration := time.Since(start)
	logging.InfoLog("Ephemeral store initialization completed %v", duration)
	return store
}

func (s *coreStore) set(key, value string, ttl time.Duration) error {
	start := time.Now()
	keyHash := utils.HashEmail(key) // Assuming keys might be emails or sensitive data
	logging.DebugLog("Ephemeral store set started [%s]", keyHash)

	if len(key) > maxKeyLength {
		logging.WarnLog("Ephemeral store set failed: key too long [%s] (length: %d, max: %d)", keyHash, len(key), maxKeyLength)
		return ErrTooLong
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.data) >= maxStoreSize {
		logging.WarnLog("Ephemeral store set failed: store full [%s] (size: %d, max: %d)", keyHash, len(s.data), maxStoreSize)
		return ErrStoreFull
	}

	s.data[key] = &item{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}

	duration := time.Since(start)
	logging.InfoLog("Ephemeral store set success [%s] ttl=%v %v", keyHash, ttl, duration)
	return nil
}

func (s *coreStore) get(key string) (string, bool) {
	start := time.Now()
	keyHash := utils.HashEmail(key)
	logging.DebugLog("Ephemeral store get started [%s]", keyHash)

	s.mu.RLock()
	defer s.mu.RUnlock()

	it, ok := s.data[key]
	if !ok {
		duration := time.Since(start)
		logging.DebugLog("Ephemeral store get: key not found [%s] %v", keyHash, duration)
		return "", false
	}

	if time.Now().After(it.expiresAt) {
		duration := time.Since(start)
		logging.DebugLog("Ephemeral store get: key expired [%s] %v", keyHash, duration)
		return "", false
	}

	duration := time.Since(start)
	logging.InfoLog("Ephemeral store get success [%s] %v", keyHash, duration)
	return it.value, true
}

// ConstantTimeEquals compares two strings in constant time to prevent timing attacks.
func ConstantTimeEquals(a, b string) bool {
	start := time.Now()
	logging.DebugLog("Constant time comparison started")

	if len(a) != len(b) {
		duration := time.Since(start)
		logging.DebugLog("Constant time comparison: length mismatch %v", duration)
		return false
	}

	result := subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
	duration := time.Since(start)

	if result {
		logging.DebugLog("Constant time comparison: match %v", duration)
	} else {
		logging.DebugLog("Constant time comparison: no match %v", duration)
	}

	return result
}

func (s *coreStore) delete(key string) {
	start := time.Now()
	keyHash := utils.HashEmail(key)
	logging.DebugLog("Ephemeral store delete started [%s]", keyHash)

	s.mu.Lock()
	defer s.mu.Unlock()

	_, existed := s.data[key]
	delete(s.data, key)

	duration := time.Since(start)
	if existed {
		logging.InfoLog("Ephemeral store delete success [%s] %v", keyHash, duration)
	} else {
		logging.DebugLog("Ephemeral store delete: key not found [%s] %v", keyHash, duration)
	}
}

func (s *coreStore) cleanup() {
	logging.InfoLog("Ephemeral store cleanup goroutine started")
	ticker := time.NewTicker(1 * time.Minute)

	for range ticker.C {
		start := time.Now()
		logging.DebugLog("Ephemeral store cleanup cycle started")

		now := time.Now()
		s.mu.Lock()

		initialSize := len(s.data)
		expiredCount := 0

		for k, v := range s.data {
			if now.After(v.expiresAt) {
				delete(s.data, k)
				expiredCount++
			}
		}

		s.mu.Unlock()

		duration := time.Since(start)
		if expiredCount > 0 {
			logging.InfoLog("Ephemeral store cleanup completed: removed %d expired items (size: %d -> %d) %v",
				expiredCount, initialSize, len(s.data), duration)
		} else {
			logging.DebugLog("Ephemeral store cleanup completed: no expired items (size: %d) %v",
				initialSize, duration)
		}
	}
}
