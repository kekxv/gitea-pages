package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// TokenStore stores user tokens with SQLite persistence
type TokenStore struct {
	mu            sync.RWMutex
	tokens        map[string]*UserToken
	registrationResults map[string]*WebhookRegistrationResult // In-memory only, updated async
	db            *sql.DB
	dbPath        string
}

// NewTokenStore creates a new token store with SQLite persistence
func NewTokenStore(dataDir string) *TokenStore {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Printf("Warning: Failed to create data directory: %v", err)
	}

	dbPath := filepath.Join(dataDir, "tokens.db")

	store := &TokenStore{
		tokens:              make(map[string]*UserToken),
		registrationResults: make(map[string]*WebhookRegistrationResult),
		dbPath:              dbPath,
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
	// Use SQLite connection string with busy_timeout to avoid blocking
	// _busy_timeout=5000 means wait up to 5 seconds if database is locked
	dsn := fmt.Sprintf("%s?_busy_timeout=5000&_journal_mode=WAL", s.dbPath)

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings for SQLite
	db.SetMaxOpenConns(1) // SQLite works best with single connection
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0) // Don't close connections

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
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
		refresh_token TEXT,
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

	// Migration: Add refresh_token column if it doesn't exist
	_, err = db.Exec(`ALTER TABLE user_tokens ADD COLUMN refresh_token TEXT`)
	if err != nil {
		// Column might already exist, ignore error
		if !strings.Contains(err.Error(), "duplicate column") {
			log.Printf("Warning: Failed to add refresh_token column (may already exist): %v", err)
		}
	}

	return nil
}

// loadFromDB loads all tokens from database into memory
func (s *TokenStore) loadFromDB() error {
	if s.db == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
		SELECT username, access_token, refresh_token, token_type, expires_at, created_at
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
		var refreshToken sql.NullString

		err := rows.Scan(
			&token.Username,
			&token.AccessToken,
			&refreshToken,
			&token.TokenType,
			&expiresAt,
			&createdAt,
		)
		if err != nil {
			log.Printf("Warning: Failed to scan token row: %v", err)
			continue
		}

		if refreshToken.Valid {
			token.RefreshToken = refreshToken.String
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
// Username is normalized to lowercase for consistent lookup
func (s *TokenStore) Set(username string, token *UserToken) {
	// Normalize username to lowercase
	normalizedUsername := strings.ToLower(username)
	token.Username = normalizedUsername

	s.mu.Lock()
	defer s.mu.Unlock()

	// Update memory
	s.tokens[normalizedUsername] = token

	// Update database
	if s.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := s.db.ExecContext(ctx, `
			INSERT OR REPLACE INTO user_tokens
			(username, access_token, refresh_token, token_type, expires_at, created_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`,
			normalizedUsername,
			token.AccessToken,
			token.RefreshToken,
			token.TokenType,
			token.ExpiresAt,
			token.CreatedAt,
		)
		cancel()
		if err != nil {
			log.Printf("Warning: Failed to save token to database: %v", err)
		} else {
			log.Printf("Token saved to database for user: %s", normalizedUsername)
		}
	}
}

// Get retrieves a user token (username normalized to lowercase)
func (s *TokenStore) Get(username string) *UserToken {
	normalizedUsername := strings.ToLower(username)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tokens[normalizedUsername]
}

// GetTokenForRepo returns the access token for a repository owner
// SECURITY: Also checks if token has expired
// Username is normalized to lowercase for consistent lookup
func (s *TokenStore) GetTokenForRepo(owner string) string {
	normalizedOwner := strings.ToLower(owner)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if token, ok := s.tokens[normalizedOwner]; ok {
		// Check if token has expired
		if !token.ExpiresAt.IsZero() && time.Now().After(token.ExpiresAt) {
			log.Printf("Token for %s has expired", normalizedOwner)
			return ""
		}
		return token.AccessToken
	}
	return ""
}

// Delete removes a user token (username normalized to lowercase)
func (s *TokenStore) Delete(username string) {
	normalizedUsername := strings.ToLower(username)
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, normalizedUsername)

	if s.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := s.db.ExecContext(ctx, "DELETE FROM user_tokens WHERE username = ?", normalizedUsername)
		cancel()
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

// SetRegistrationResult stores the webhook registration result for a user
// Username is normalized to lowercase
func (s *TokenStore) SetRegistrationResult(username string, result *WebhookRegistrationResult) {
	normalizedUsername := strings.ToLower(username)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registrationResults[normalizedUsername] = result
}

// GetRegistrationResult retrieves the webhook registration result for a user
// Username is normalized to lowercase
func (s *TokenStore) GetRegistrationResult(username string) *WebhookRegistrationResult {
	normalizedUsername := strings.ToLower(username)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.registrationResults[normalizedUsername]
}