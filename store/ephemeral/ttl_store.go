package ephemeral

import "time"

type TTLStore struct {
	core *coreStore
}

func NewTTLStore() *TTLStore {
	return &TTLStore{core: newCoreStore()}
}

func (s *TTLStore) Set(email string, ttl time.Duration) error {
	return s.core.set(email, "", ttl)
}

func (s *TTLStore) Exists(email string) bool {
	_, exists := s.core.get(email)
	return exists
}

func (s *TTLStore) Delete(email string) {
	s.core.delete(email)
}
