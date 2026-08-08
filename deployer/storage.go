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

	_ "modernc.org/sqlite"
)

// TokenStore stores user tokens with SQLite persistence
type TokenStore struct {
	mu                  sync.RWMutex
	tokens              map[string]*UserToken
	registrationResults map[string]*WebhookRegistrationResult // In-memory only, updated async
	db                  *sql.DB
	dbPath              string
	cleanupStop         chan struct{}
	cleanupDone         chan struct{}
	closeOnce           sync.Once
	closeErr            error
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
	store.startDeliveryCleanup()

	log.Printf("Token store initialized with SQLite persistence: %s", dbPath)
	return store
}

// initDB initializes the SQLite database
func (s *TokenStore) initDB() error {
	// Configure the pure-Go SQLite driver to wait briefly for locks and use WAL.
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", s.dbPath)

	db, err := sql.Open("sqlite", dsn)
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

	// Create tables if they do not exist.
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
	CREATE TABLE IF NOT EXISTS hook_credentials (
		hook_key TEXT PRIMARY KEY,
		secret BLOB NOT NULL,
		principal_username TEXT NOT NULL,
		scope_type TEXT NOT NULL CHECK(scope_type IN ('user','organization')),
		scope_name TEXT NOT NULL,
		gitea_hook_id INTEGER NOT NULL,
		created_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS webhook_deliveries (
		hook_key TEXT NOT NULL,
		delivery_id TEXT NOT NULL,
		received_at DATETIME NOT NULL,
		PRIMARY KEY (hook_key, delivery_id)
	);
	CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_received_at ON webhook_deliveries(received_at);
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}
	if err := s.cleanupExpiredDeliveries(context.Background()); err != nil {
		return fmt.Errorf("failed to clean expired webhook deliveries: %w", err)
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

const (
	deliveryRetentionPeriod = 7 * 24 * time.Hour
	deliveryCleanupInterval = 24 * time.Hour
)

func (s *TokenStore) startDeliveryCleanup() {
	if s.db == nil {
		return
	}
	s.cleanupStop = make(chan struct{})
	s.cleanupDone = make(chan struct{})
	go func() {
		defer close(s.cleanupDone)
		ticker := time.NewTicker(deliveryCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := s.cleanupExpiredDeliveries(ctx); err != nil {
					log.Printf("Warning: Failed to clean expired webhook deliveries: %v", err)
				}
				cancel()
			case <-s.cleanupStop:
				return
			}
		}
	}()
}

func (s *TokenStore) cleanupExpiredDeliveries(ctx context.Context) error {
	if s.db == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM webhook_deliveries WHERE received_at < ?`, time.Now().Add(-deliveryRetentionPeriod).UTC())
	return err
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
	s.closeOnce.Do(func() {
		if s.cleanupStop != nil {
			close(s.cleanupStop)
			<-s.cleanupDone
		}
		if s.db != nil {
			s.closeErr = s.db.Close()
		}
	})
	return s.closeErr
}

// GetHook retrieves the credential selected by a webhook authorization key.
func (s *TokenStore) GetHook(ctx context.Context, key string) (*HookCredential, error) {
	if s.db == nil {
		return nil, fmt.Errorf("hook credential storage is unavailable")
	}

	var credential HookCredential
	err := s.db.QueryRowContext(ctx, `
		SELECT hook_key, secret, principal_username, scope_type, scope_name, gitea_hook_id
		FROM hook_credentials
		WHERE hook_key = ?
	`, key).Scan(
		&credential.Key,
		&credential.Secret,
		&credential.PrincipalUsername,
		&credential.ScopeType,
		&credential.ScopeName,
		&credential.GiteaHookID,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &credential, nil
}

// PutHook creates or updates the credential for a user- or organization-level hook.
func (s *TokenStore) PutHook(ctx context.Context, credential HookCredential) error {
	if s.db == nil {
		return fmt.Errorf("hook credential storage is unavailable")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO hook_credentials
			(hook_key, secret, principal_username, scope_type, scope_name, gitea_hook_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(hook_key) DO UPDATE SET
			secret = excluded.secret,
			principal_username = excluded.principal_username,
			scope_type = excluded.scope_type,
			scope_name = excluded.scope_name,
			gitea_hook_id = excluded.gitea_hook_id,
			created_at = excluded.created_at
	`,
		credential.Key,
		credential.Secret,
		credential.PrincipalUsername,
		credential.ScopeType,
		credential.ScopeName,
		credential.GiteaHookID,
		time.Now().UTC(),
	)
	return err
}

// RecordDelivery records a delivery exactly once for a hook.
func (s *TokenStore) RecordDelivery(ctx context.Context, hookKey, deliveryID string, receivedAt time.Time) (bool, error) {
	if s.db == nil {
		return false, fmt.Errorf("webhook delivery storage is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `
		INSERT INTO webhook_deliveries (hook_key, delivery_id, received_at)
		VALUES (?, ?, ?)
		ON CONFLICT(hook_key, delivery_id) DO NOTHING
	`, hookKey, deliveryID, receivedAt.UTC())
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return inserted == 1, nil
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
