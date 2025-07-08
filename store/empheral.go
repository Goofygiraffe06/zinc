package store

import (
	"errors"
	"sync"
	"time"
)

const (
	MaxEmailLength = 254
	MaxEntries     = 10_000
	GCInterval     = 30 * time.Second
)

var (
	ErrTooLong   = errors.New("email exceeds max length")
	ErrStoreFull = errors.New("ephemeral store full")
)

type EphemeralStore struct {
	mu   sync.RWMutex
	data map[string]time.Time
}

func NewEphemeralStore() *EphemeralStore {
	s := &EphemeralStore{
		data: make(map[string]time.Time),
	}
	go s.gcLoop()
	return s
}

func (s *EphemeralStore) Set(email string, ttl time.Duration) error {
	if len(email) > MaxEmailLength {
		return ErrTooLong
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.data) >= MaxEntries {
		return ErrStoreFull
	}

	s.data[email] = time.Now().Add(ttl)
	return nil
}

func (s *EphemeralStore) Exists(email string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	expiry, ok := s.data[email]
	return ok && time.Now().Before(expiry)
}

func (s *EphemeralStore) Delete(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, email)
}

func (s *EphemeralStore) gcLoop() {
	ticker := time.NewTicker(GCInterval)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for email, expiry := range s.data {
			if now.After(expiry) {
				delete(s.data, email)
			}
		}
		s.mu.Unlock()
	}
}
