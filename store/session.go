package store

import (
	"sync"
	"time"
)

type SessionStore struct {
	sessions map[string]time.Time
	mu       sync.Mutex
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]time.Time),
	}
}

// Start a new session. Returns false if one already exists.
func (s *SessionStore) Start(email string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[email]; exists {
		return false
	}

	s.sessions[email] = time.Now()
	return true
}

// IsActive returns true if a session is active.
func (s *SessionStore) IsActive(email string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, exists := s.sessions[email]
	return exists
}

// End deletes the session.
func (s *SessionStore) End(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, email)
}
