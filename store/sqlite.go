package store

import (
	"database/sql"
	"log"

	"github.com/Goofygiraffe06/zinc/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (or creates) a SQLite DB at the given path and initializes the schema.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	// Create the users table if it doesn't exist
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
			email TEXT PRIMARY KEY,
			username TEXT,
			public_key TEXT
		);`
	if _, err := db.Exec(createTableQuery); err != nil {
		log.Fatal("Failed to create users table:", err)
	}

	return &SQLiteStore{db: db}, nil
}

// AddUser inserts a new user into the DB
func (s *SQLiteStore) AddUser(user models.User) error {
	_, err := s.db.Exec(`
		INSERT INTO users (email, username, public_key)
		VALUES (?, ?, ?)`,
		user.Email, user.Username, user.PublicKey,
	)
	return err
}

// GetUser retrieves a user by email. Returns (user, true) if found, or (_, false).
func (s *SQLiteStore) GetUser(email string) (models.User, bool) {
	row := s.db.QueryRow(`
		SELECT email, username, public_key
		FROM users
		WHERE email = ?`, email)

	var user models.User
	err := row.Scan(&user.Email, &user.Username, &user.PublicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			return models.User{}, false
		}
		log.Println("failed to get user", err)
		return models.User{}, false
	}

	return user, true
}

// Exists returns true if a user with the given email exists.
func (s *SQLiteStore) Exists(email string) bool {
	_, found := s.GetUser(email)
	return found
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
