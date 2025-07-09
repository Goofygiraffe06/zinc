package ephemeral

import (
	"errors"
	"sync"
	"time"
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
	data map[string]item
	mu   sync.RWMutex
}

func newCoreStore() *coreStore {
	store := &coreStore{
		data: make(map[string]item),
	}
	go store.cleanup()
	return store
}

func (s *coreStore) set(key, value string, ttl time.Duration) error {
	if len(key) > maxKeyLength {
		return ErrTooLong
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.data) >= maxStoreSize {
		return ErrStoreFull
	}
	s.data[key] = item{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (s *coreStore) get(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	it, ok := s.data[key]
	if !ok || time.Now().After(it.expiresAt) {
		return "", false
	}
	return it.value, true
}

func (s *coreStore) delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
}

func (s *coreStore) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for k, v := range s.data {
			if now.After(v.expiresAt) {
				delete(s.data, k)
			}
		}
		s.mu.Unlock()
	}
}
