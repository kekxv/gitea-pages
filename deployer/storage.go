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
	cipher              *TokenCipher
	db                  *sql.DB
	dbPath              string
	cleanupStop         chan struct{}
	cleanupDone         chan struct{}
	closeOnce           sync.Once
	closeErr            error
}

// NewTokenStore creates a new encrypted token store with SQLite persistence.
func NewTokenStore(dataDir string, key []byte) (*TokenStore, error) {
	cipher, err := NewTokenCipher(key)
	if err != nil {
		return nil, err
	}

	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("create token data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "tokens.db")

	store := &TokenStore{
		tokens:              make(map[string]*UserToken),
		registrationResults: make(map[string]*WebhookRegistrationResult),
		cipher:              cipher,
		dbPath:              dbPath,
	}

	if err := store.initDB(); err != nil {
		return nil, err
	}

	if err := store.loadFromDB(); err != nil {
		_ = store.Close()
		return nil, err
	}
	store.startDeliveryCleanup()

	log.Printf("Token store initialized with SQLite persistence: %s", dbPath)
	return store, nil
}

// initDB initializes the SQLite database
func (s *TokenStore) initDB() (err error) {
	// Configure the pure-Go SQLite driver to wait briefly for locks and use WAL.
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", s.dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()

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

	// Restrict database file permissions
	if err := os.Chmod(s.dbPath, 0600); err != nil {
		log.Printf("Warning: Failed to set database permissions: %v", err)
	}

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin token schema migration: %w", err)
	}
	defer tx.Rollback()

	// Create the encrypted token schema and preserve existing hook data.
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS user_tokens_v2 (
		username TEXT PRIMARY KEY,
		access_token_ciphertext BLOB NOT NULL,
		refresh_token_ciphertext BLOB,
		token_type TEXT,
		expires_at DATETIME,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_user_tokens_v2_username ON user_tokens_v2(username);
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

	_, err = tx.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	var hasLegacyTable int
	err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'user_tokens')`).Scan(&hasLegacyTable)
	if err != nil {
		return fmt.Errorf("inspect legacy token schema: %w", err)
	}
	if hasLegacyTable == 1 {
		var hasPlaintextRows int
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM user_tokens LIMIT 1)`).Scan(&hasPlaintextRows); err != nil {
			return fmt.Errorf("inspect legacy tokens: %w", err)
		}
		if hasPlaintextRows == 1 {
			return fmt.Errorf("plaintext user_tokens rows detected; run the Task 10 token migration command before starting the server")
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit token schema migration: %w", err)
	}

	s.db = db
	if err := s.cleanupExpiredDeliveries(context.Background()); err != nil {
		return fmt.Errorf("failed to clean expired webhook deliveries: %w", err)
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
		SELECT username, access_token_ciphertext, refresh_token_ciphertext, token_type, expires_at, created_at
		FROM user_tokens_v2
	`)
	if err != nil {
		return fmt.Errorf("failed to query tokens: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var token UserToken
		var expiresAt, createdAt sql.NullTime
		var accessTokenCiphertext []byte
		var refreshTokenCiphertext []byte

		err := rows.Scan(
			&token.Username,
			&accessTokenCiphertext,
			&refreshTokenCiphertext,
			&token.TokenType,
			&expiresAt,
			&createdAt,
		)
		if err != nil {
			return fmt.Errorf("scan token row: %w", err)
		}

		accessToken, err := s.cipher.Open(accessTokenCiphertext)
		if err != nil {
			return ErrTokenDecrypt
		}
		token.AccessToken = string(accessToken)
		if refreshTokenCiphertext != nil {
			refreshToken, err := s.cipher.Open(refreshTokenCiphertext)
			if err != nil {
				return ErrTokenDecrypt
			}
			token.RefreshToken = string(refreshToken)
		}
		if expiresAt.Valid {
			token.ExpiresAt = expiresAt.Time
		}
		if createdAt.Valid {
			token.CreatedAt = createdAt.Time
		}

		tokenCopy := token
		s.tokens[token.Username] = &tokenCopy
		count++
	}

	log.Printf("Loaded %d tokens from database", count)
	return rows.Err()
}

// Set stores a user token (in memory and database)
// Username is normalized to lowercase for consistent lookup
func (s *TokenStore) Set(username string, token *UserToken) {
	if token == nil {
		return
	}
	// Normalize username to lowercase
	normalizedUsername := strings.ToLower(username)
	tokenCopy := *token
	tokenCopy.Username = normalizedUsername

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.writeToken(&tokenCopy); err != nil {
		log.Printf("Warning: Failed to save token for user %s: %v", normalizedUsername, err)
		return
	}
	s.tokens[normalizedUsername] = &tokenCopy
	log.Printf("Token saved to database for user: %s", normalizedUsername)
}

// UpdateToken atomically replaces one token after applying update to a value copy.
func (s *TokenStore) UpdateToken(username string, update func(UserToken) UserToken) error {
	normalizedUsername := strings.ToLower(username)
	s.mu.Lock()
	defer s.mu.Unlock()

	current := s.tokens[normalizedUsername]
	if current == nil {
		return fmt.Errorf("token not found for user %s", normalizedUsername)
	}
	updated := update(*current)
	updated.Username = normalizedUsername
	if err := s.writeToken(&updated); err != nil {
		return err
	}
	s.tokens[normalizedUsername] = &updated
	return nil
}

func (s *TokenStore) writeToken(token *UserToken) error {
	if s.db == nil || s.cipher == nil {
		return fmt.Errorf("token storage is unavailable")
	}
	accessTokenCiphertext, err := s.cipher.Seal([]byte(token.AccessToken))
	if err != nil {
		return fmt.Errorf("encrypt access token: %w", err)
	}
	var refreshTokenCiphertext []byte
	if token.RefreshToken != "" {
		refreshTokenCiphertext, err = s.cipher.Seal([]byte(token.RefreshToken))
		if err != nil {
			return fmt.Errorf("encrypt refresh token: %w", err)
		}
	}
	if token.CreatedAt.IsZero() {
		token.CreatedAt = time.Now().UTC()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO user_tokens_v2
			(username, access_token_ciphertext, refresh_token_ciphertext, token_type, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			access_token_ciphertext = excluded.access_token_ciphertext,
			refresh_token_ciphertext = excluded.refresh_token_ciphertext,
			token_type = excluded.token_type,
			expires_at = excluded.expires_at,
			created_at = excluded.created_at
	`, token.Username, accessTokenCiphertext, refreshTokenCiphertext, token.TokenType, token.ExpiresAt, token.CreatedAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Get retrieves a user token (username normalized to lowercase)
func (s *TokenStore) Get(username string) *UserToken {
	normalizedUsername := strings.ToLower(username)
	s.mu.RLock()
	defer s.mu.RUnlock()
	token := s.tokens[normalizedUsername]
	if token == nil {
		return nil
	}
	copy := *token
	return &copy
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
		_, err := s.db.ExecContext(ctx, "DELETE FROM user_tokens_v2 WHERE username = ?", normalizedUsername)
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
