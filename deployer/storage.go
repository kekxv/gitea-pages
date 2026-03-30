package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// TokenStore stores user tokens with SQLite persistence
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*UserToken
	db     *sql.DB
	dbPath string
}

// NewTokenStore creates a new token store with SQLite persistence
func NewTokenStore(dataDir string) *TokenStore {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Printf("Warning: Failed to create data directory: %v", err)
	}

	dbPath := filepath.Join(dataDir, "tokens.db")

	store := &TokenStore{
		tokens: make(map[string]*UserToken),
		dbPath: dbPath,
	}

	// Initialize database
	if err := store.initDB(); err != nil {
		log.Printf("Warning: Failed to initialize database, using memory-only mode: %v", err)
		return store
	}

	// Load existing tokens from database
	if err := store.loadFromDB(); err != nil {
		log.Printf("Warning: Failed to load tokens from database: %v", err)
	}

	log.Printf("Token store initialized with SQLite persistence: %s", dbPath)
	return store
}

// initDB initializes the SQLite database
func (s *TokenStore) initDB() error {
	// Set umask for this process to ensure new files have restricted permissions
	// Alternatively, we can just Chmod after creation.
	db, err := sql.Open("sqlite3", s.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	s.db = db

	// Restrict database file permissions
	if err := os.Chmod(s.dbPath, 0600); err != nil {
		log.Printf("Warning: Failed to set database permissions: %v", err)
	}

	// Create table if not exists
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS user_tokens (
		username TEXT PRIMARY KEY,
		access_token TEXT NOT NULL,
		token_type TEXT,
		expires_at DATETIME,
		created_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_username ON user_tokens(username);
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	return nil
}

// loadFromDB loads all tokens from database into memory
func (s *TokenStore) loadFromDB() error {
	if s.db == nil {
		return nil
	}

	rows, err := s.db.Query(`
		SELECT username, access_token, token_type, expires_at, created_at
		FROM user_tokens
	`)
	if err != nil {
		return fmt.Errorf("failed to query tokens: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var token UserToken
		var expiresAt, createdAt sql.NullTime

		err := rows.Scan(
			&token.Username,
			&token.AccessToken,
			&token.TokenType,
			&expiresAt,
			&createdAt,
		)
		if err != nil {
			log.Printf("Warning: Failed to scan token row: %v", err)
			continue
		}

		if expiresAt.Valid {
			token.ExpiresAt = expiresAt.Time
		}
		if createdAt.Valid {
			token.CreatedAt = createdAt.Time
		}

		s.tokens[token.Username] = &token
		count++
	}

	log.Printf("Loaded %d tokens from database", count)
	return nil
}

// Set stores a user token (in memory and database)
func (s *TokenStore) Set(username string, token *UserToken) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update memory
	s.tokens[username] = token

	// Update database
	if s.db != nil {
		_, err := s.db.Exec(`
			INSERT OR REPLACE INTO user_tokens
			(username, access_token, token_type, expires_at, created_at)
			VALUES (?, ?, ?, ?, ?)
		`,
			token.Username,
			token.AccessToken,
			token.TokenType,
			token.ExpiresAt,
			token.CreatedAt,
		)
		if err != nil {
			log.Printf("Warning: Failed to save token to database: %v", err)
		} else {
			log.Printf("Token saved to database for user: %s", username)
		}
	}
}

// Get retrieves a user token
func (s *TokenStore) Get(username string) *UserToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tokens[username]
}

// GetTokenForRepo returns the access token for a repository owner
// SECURITY: Also checks if token has expired
func (s *TokenStore) GetTokenForRepo(owner string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if token, ok := s.tokens[owner]; ok {
		// Check if token has expired
		if !token.ExpiresAt.IsZero() && time.Now().After(token.ExpiresAt) {
			log.Printf("Token for %s has expired", owner)
			return ""
		}
		return token.AccessToken
	}
	return ""
}

// Delete removes a user token
func (s *TokenStore) Delete(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, username)

	if s.db != nil {
		_, err := s.db.Exec("DELETE FROM user_tokens WHERE username = ?", username)
		if err != nil {
			log.Printf("Warning: Failed to delete token from database: %v", err)
		}
	}
}

// List returns all usernames with tokens
func (s *TokenStore) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	usernames := make([]string, 0, len(s.tokens))
	for username := range s.tokens {
		usernames = append(usernames, username)
	}
	return usernames
}

// Close closes the database connection
func (s *TokenStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}