package ephemeral

import (
    "time"
    "github.com/Goofygiraffe06/zinc/internal/logging"
)

type NonceStore struct {
    core *coreStore
}

func NewNonceStore() *NonceStore {
    store := &NonceStore{core: newCoreStore()}
    logging.DebugLog("Nonce store created")
    return store
}

func (s *NonceStore) Set(email, nonce string, ttl time.Duration) error {
    err := s.core.set(email, nonce, ttl)
    if err != nil {
        logging.DebugLog("Nonce store set failed: %v", err)
    }
    return err
}

func (s *NonceStore) Get(email string) (string, bool) {
    nonce, found := s.core.get(email)
    return nonce, found
}

func (s *NonceStore) Delete(email string) {
    s.core.delete(email)
}