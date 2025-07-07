package store

import (
	"database/sql"
	"errors"
	"log"
	"strings"

	"github.com/Goofygiraffe06/zinc/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

type SQLiteStore struct {
	db *sql.DB
}

var ErrUserExists = errors.New("user already exists")

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		email TEXT PRIMARY KEY NOT NULL CHECK(email <> ''),
		username TEXT NOT NULL CHECK(username <> ''),
		public_key TEXT NOT NULL CHECK(public_key <> '')
	);`

	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) AddUser(user models.User) error {
	_, err := s.db.Exec(`
		INSERT INTO users (email, username, public_key)
		VALUES (?, ?, ?)`,
		user.Email, user.Username, user.PublicKey,
	)

	if err != nil {
		// Handle unique constraint violation gracefully
		if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "constraint failed") {
			return ErrUserExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStore) GetUser(email string) (models.User, bool) {
	var user models.User
	err := s.db.QueryRow(`
		SELECT email, username, public_key
		FROM users
		WHERE email = ?`, email).Scan(&user.Email, &user.Username, &user.PublicKey)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, false
		}
		log.Println("store.GetUser error:", err)
		return models.User{}, false
	}

	return user, true
}

func (s *SQLiteStore) Exists(email string) bool {
	_, found := s.GetUser(email)
	return found
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
