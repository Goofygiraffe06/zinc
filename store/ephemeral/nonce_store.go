package ephemeral

import "time"

type NonceStore struct {
	core *coreStore
}

func NewNonceStore() *NonceStore {
	return &NonceStore{core: newCoreStore()}
}

func (s *NonceStore) Set(email, nonce string, ttl time.Duration) error {
	return s.core.set(email, nonce, ttl)
}

func (s *NonceStore) Get(email string) (string, bool) {
	return s.core.get(email)
}

func (s *NonceStore) Delete(email string) {
	s.core.delete(email)
}
