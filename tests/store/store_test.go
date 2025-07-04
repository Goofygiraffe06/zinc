package store_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Goofygiraffe06/zinc/internal/models"
	"github.com/Goofygiraffe06/zinc/store" 
)

// setupTestDB creates a temporary database for testing
func setupTestDB(t *testing.T) (*store.SQLiteStore, func()) {
	// Create a temporary directory for test databases
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	storeInstance, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Return cleanup function
	cleanup := func() {
		storeInstance.Close()
		os.Remove(dbPath)
	}

	return storeInstance, cleanup
}

func TestNewSQLiteStore(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	storeInstance, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer storeInstance.Close()

	// Verify the database connection is working
	if storeInstance == nil {
		t.Error("Store instance is nil")
	}

	// Test that we can add and retrieve a user (indirect table verification)
	testUser := models.User{
		Email:     "test@example.com",
		Username:  "testuser",
		PublicKey: "test-key",
	}

	err = storeInstance.AddUser(testUser)
	if err != nil {
		t.Errorf("Failed to add user to verify table creation: %v", err)
	}
}

func TestAddUser(t *testing.T) {
	storeInstance, cleanup := setupTestDB(t)
	defer cleanup()

	testCases := []struct {
		name        string
		user        models.User
		expectError bool
	}{
		{
			name: "valid user",
			user: models.User{
				Email:     "test@example.com",
				Username:  "testuser",
				PublicKey: "test-public-key",
			},
			expectError: false,
		},
		{
			name: "duplicate email",
			user: models.User{
				Email:     "test@example.com", // Same email as above
				Username:  "testuser2",
				PublicKey: "test-public-key-2",
			},
			expectError: true,
		},
		{
			name: "empty email",
			user: models.User{
				Email:     "",
				Username:  "testuser3",
				PublicKey: "test-public-key-3",
			},
			expectError: true,
		},
		{
			name: "empty username",
			user: models.User{
				Email:     "test3@example.com",
				Username:  "",
				PublicKey: "test-public-key-3",
			},
			expectError: true,
		},
		{
			name: "empty public key",
			user: models.User{
				Email:     "test4@example.com",
				Username:  "testuser4",
				PublicKey: "",
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := storeInstance.AddUser(tc.user)

			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	storeInstance, cleanup := setupTestDB(t)
	defer cleanup()

	// Add a test user
	testUser := models.User{
		Email:     "test@example.com",
		Username:  "testuser",
		PublicKey: "test-public-key",
	}

	err := storeInstance.AddUser(testUser)
	if err != nil {
		t.Fatalf("Failed to add test user: %v", err)
	}

	t.Run("existing user", func(t *testing.T) {
		user, found := storeInstance.GetUser("test@example.com")

		if !found {
			t.Error("User should be found")
		}

		if user.Email != testUser.Email {
			t.Errorf("Expected email %s, got %s", testUser.Email, user.Email)
		}
		if user.Username != testUser.Username {
			t.Errorf("Expected username %s, got %s", testUser.Username, user.Username)
		}
		if user.PublicKey != testUser.PublicKey {
			t.Errorf("Expected public key %s, got %s", testUser.PublicKey, user.PublicKey)
		}
	})

	t.Run("non-existing user", func(t *testing.T) {
		_, found := storeInstance.GetUser("nonexistent@example.com")

		if found {
			t.Error("User should not be found")
		}
	})

	t.Run("empty email", func(t *testing.T) {
		_, found := storeInstance.GetUser("")

		if found {
			t.Error("User should not be found for empty email")
		}
	})
}

func TestExists(t *testing.T) {
	storeInstance, cleanup := setupTestDB(t)
	defer cleanup()

	// Add a test user
	testUser := models.User{
		Email:     "test@example.com",
		Username:  "testuser",
		PublicKey: "test-public-key",
	}

	err := storeInstance.AddUser(testUser)
	if err != nil {
		t.Fatalf("Failed to add test user: %v", err)
	}

	t.Run("existing user", func(t *testing.T) {
		exists := storeInstance.Exists("test@example.com")
		if !exists {
			t.Error("User should exist")
		}
	})

	t.Run("non-existing user", func(t *testing.T) {
		exists := storeInstance.Exists("nonexistent@example.com")
		if exists {
			t.Error("User should not exist")
		}
	})

	t.Run("empty email", func(t *testing.T) {
		exists := storeInstance.Exists("")
		if exists {
			t.Error("User should not exist for empty email")
		}
	})
}

func TestClose(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	storeInstance, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}

	err = storeInstance.Close()
	if err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// Verify database is closed by trying to use it
	testUser := models.User{
		Email:     "test@example.com",
		Username:  "testuser",
		PublicKey: "test-key",
	}

	err = storeInstance.AddUser(testUser)
	if err == nil {
		t.Error("Expected error when using closed database")
	}
}

func TestMultipleUsers(t *testing.T) {
	storeInstance, cleanup := setupTestDB(t)
	defer cleanup()

	users := []models.User{
		{Email: "user1@example.com", Username: "user1", PublicKey: "key1"},
		{Email: "user2@example.com", Username: "user2", PublicKey: "key2"},
		{Email: "user3@example.com", Username: "user3", PublicKey: "key3"},
	}

	// Add all users
	for _, user := range users {
		err := storeInstance.AddUser(user)
		if err != nil {
			t.Fatalf("Failed to add user %s: %v", user.Email, err)
		}
	}

	// Verify all users can be retrieved
	for _, expectedUser := range users {
		user, found := storeInstance.GetUser(expectedUser.Email)
		if !found {
			t.Errorf("User %s not found", expectedUser.Email)
			continue
		}

		if user.Email != expectedUser.Email ||
			user.Username != expectedUser.Username ||
			user.PublicKey != expectedUser.PublicKey {
			t.Errorf("User data mismatch for %s", expectedUser.Email)
		}

		if !storeInstance.Exists(expectedUser.Email) {
			t.Errorf("Exists() returned false for %s", expectedUser.Email)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	storeInstance, cleanup := setupTestDB(t)
	defer cleanup()

	// Test concurrent reads and writes
	done := make(chan bool)

	// Goroutine 1: Add users
	go func() {
		for i := 0; i < 10; i++ {
			user := models.User{
				Email:     fmt.Sprintf("user%d@example.com", i),
				Username:  fmt.Sprintf("user%d", i),
				PublicKey: fmt.Sprintf("key%d", i),
			}
			storeInstance.AddUser(user)
		}
		done <- true
	}()

	// Goroutine 2: Read users
	go func() {
		for i := 0; i < 10; i++ {
			email := fmt.Sprintf("user%d@example.com", i)
			storeInstance.GetUser(email)
			storeInstance.Exists(email)
		}
		done <- true
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	// Verify some users were added
	count := 0
	for i := 0; i < 10; i++ {
		email := fmt.Sprintf("user%d@example.com", i)
		if storeInstance.Exists(email) {
			count++
		}
	}

	if count == 0 {
		t.Error("No users were added during concurrent access test")
	}
}
