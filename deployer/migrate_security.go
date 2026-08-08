package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const securityMigrationManifestVersion = 1

const migrationGiteaPageLimit = 100

// SecurityMigrationConfig contains every input required by the offline
// credential migration. It deliberately accepts paths and secrets directly so
// the HTTP server never needs to participate in a migration.
type SecurityMigrationConfig struct {
	DatabasePath            string
	BackupPath              string
	ManifestPath            string
	TokenEncryptionKey      []byte
	LegacyWebhookSecret     []byte
	GiteaAPIURL             string
	WebhookURL              string
	SkipFailedOrganizations bool
	HTTPClient              *http.Client
}

// LegacyHookRestoreConfig contains the minimum inputs required to restore
// Gitea hook configuration before an operator restores the v1 database.
type LegacyHookRestoreConfig struct {
	ManifestPath        string
	TokenEncryptionKey  []byte
	LegacyWebhookSecret []byte
	HTTPClient          *http.Client
}

type securityMigrationManifest struct {
	Version   int                        `json:"version"`
	CreatedAt time.Time                  `json:"created_at"`
	Hooks     []legacyHookRollbackRecord `json:"hooks"`
}

// legacyHookRollbackRecord intentionally excludes the legacy secret. Restore
// obtains that value only from LEGACY_WEBHOOK_SECRET_FILE at execution time.
// The entire JSON document is encrypted before it reaches disk, protecting
// access tokens and historical authorization headers as well.
type legacyHookRollbackRecord struct {
	GiteaAPIURL         string    `json:"gitea_api_url"`
	AccessToken         string    `json:"access_token"`
	ScopeType           HookScope `json:"scope_type"`
	ScopeName           string    `json:"scope_name"`
	GiteaHookID         int64     `json:"gitea_hook_id"`
	URL                 string    `json:"url"`
	ContentType         string    `json:"content_type"`
	Events              []string  `json:"events"`
	Active              bool      `json:"active"`
	BranchFilter        string    `json:"branch_filter"`
	AuthorizationHeader string    `json:"authorization_header"`
}

// RunSecurityMigration rotates legacy hooks and converts v1 plaintext token
// rows in one SQLite transaction. External hook changes are reversed in-memory
// if a required migration step fails before commit.
func RunSecurityMigration(ctx context.Context, config SecurityMigrationConfig) (err error) {
	if err := validateSecurityMigrationConfig(config); err != nil {
		return err
	}
	cipher, err := NewTokenCipher(config.TokenEncryptionKey)
	if err != nil {
		return fmt.Errorf("create migration cipher: %w", err)
	}
	db, err := openMigrationDatabase(config.DatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("acquire exclusive SQLite migration lock: %w", err)
	}
	defer tx.Rollback()
	if err := createSecureStorageSchema(ctx, tx); err != nil {
		return err
	}

	tokens, err := readLegacyTokens(ctx, tx)
	if err != nil {
		return err
	}
	authorizers, err := migrationOrganizationAuthorizers(ctx, tx)
	if err != nil {
		return err
	}
	client := migrationGiteaClient{apiURL: strings.TrimSuffix(config.GiteaAPIURL, "/"), httpClient: config.HTTPClient}
	if client.httpClient == nil {
		client.httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	var updated []legacyHookRollbackRecord
	fail := func(cause error) error {
		rollbackErr := rollbackMigratedHooks(ctx, client, updated, config.LegacyWebhookSecret)
		if rollbackErr != nil {
			return fmt.Errorf("%w; Gitea hook rollback failed: %v", cause, rollbackErr)
		}
		return cause
	}

	users := make(map[string]UserToken, len(tokens))
	for _, token := range tokens {
		token.Username = strings.ToLower(token.Username)
		users[token.Username] = token
		if err := insertEncryptedMigrationToken(ctx, tx, cipher, token); err != nil {
			return fail(fmt.Errorf("encrypt token for %s: %w", token.Username, err))
		}
		principal := HookPrincipal{Username: token.Username, ScopeType: ScopeUser, ScopeName: token.Username}
		rotated, err := rotateLegacyHooks(ctx, tx, client, config, token.AccessToken, principal)
		if err != nil {
			return fail(fmt.Errorf("rotate user hook for %s: %w", token.Username, err))
		}
		updated = append(updated, rotated...)
	}

	organizations := discoverMigrationOrganizations(ctx, client, users, authorizers)
	for _, organization := range sortedKeys(organizations) {
		candidates := organizations[organization]
		var rotateErr error
		var rotated []legacyHookRollbackRecord
		var principal HookPrincipal
		attempted := false
		for _, username := range candidates {
			token, ok := users[username]
			if !ok {
				continue
			}
			attempted = true
			principal = HookPrincipal{Username: username, ScopeType: ScopeOrganization, ScopeName: organization}
			rotated, rotateErr = rotateLegacyHooks(ctx, tx, client, config, token.AccessToken, principal)
			if rotateErr == nil {
				break
			}
		}
		if !attempted {
			rotateErr = errors.New("no retained OAuth token for organization authorizer")
		}
		if rotateErr != nil {
			if config.SkipFailedOrganizations {
				logMigrationOrganizationManualAction(organization, rotateErr)
				continue
			}
			return fail(fmt.Errorf("rotate organization hook for %s: %w", organization, rotateErr))
		}
		updated = append(updated, rotated...)
		if len(rotated) == 0 {
			continue
		}
		for _, username := range candidates {
			if _, ok := users[username]; !ok {
				continue
			}
			if err := putMigrationOrganizationAuthorizer(ctx, tx, organization, username, rotated[0].GiteaHookID, principal); err != nil {
				return fail(fmt.Errorf("retain organization authorizer for %s: %w", organization, err))
			}
		}
	}

	if _, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS user_tokens`); err != nil {
		return fail(fmt.Errorf("remove plaintext user tokens: %w", err))
	}
	if err := writeEncryptedMigrationManifest(config.ManifestPath, cipher, securityMigrationManifest{
		Version: securityMigrationManifestVersion, CreatedAt: time.Now().UTC(), Hooks: updated,
	}); err != nil {
		return fail(err)
	}
	manifestWritten := true
	if err := tx.Commit(); err != nil {
		if manifestWritten {
			_ = os.Remove(config.ManifestPath)
		}
		return fail(fmt.Errorf("commit security migration: %w", err))
	}
	return nil
}

func validateSecurityMigrationConfig(config SecurityMigrationConfig) error {
	if config.DatabasePath == "" || config.BackupPath == "" || config.ManifestPath == "" {
		return errors.New("database path, --backup, and --manifest are required")
	}
	databasePath, err := filepath.Abs(config.DatabasePath)
	if err != nil {
		return fmt.Errorf("resolve database path: %w", err)
	}
	backupPath, err := filepath.Abs(config.BackupPath)
	if err != nil {
		return fmt.Errorf("resolve backup path: %w", err)
	}
	if databasePath == backupPath {
		return errors.New("backup path must differ from tokens.db")
	}
	info, err := os.Stat(config.BackupPath)
	if err != nil {
		return fmt.Errorf("verify backup path: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fmt.Errorf("backup file must be a regular file with mode 0600")
	}
	if _, err := os.Stat(config.DatabasePath); err != nil {
		return fmt.Errorf("verify token database: %w", err)
	}
	if _, err := NewTokenCipher(config.TokenEncryptionKey); err != nil {
		return err
	}
	if len(config.LegacyWebhookSecret) == 0 {
		return errors.New("legacy webhook secret is required")
	}
	if _, err := parseHTTPURL(config.GiteaAPIURL); err != nil {
		return fmt.Errorf("invalid Gitea API URL: %w", err)
	}
	if _, err := parseHTTPURL(config.WebhookURL); err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	if _, err := os.Stat(config.ManifestPath); err == nil {
		return fmt.Errorf("rollback manifest already exists: %s", config.ManifestPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect rollback manifest path: %w", err)
	}
	return nil
}

func openMigrationDatabase(path string) (*sql.DB, error) {
	// _txlock=exclusive causes the driver's transaction begin to acquire the
	// SQLite exclusive lock, preventing another process from observing partial
	// v2 state while the offline migration is in progress.
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_txlock=exclusive", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open token database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

func readLegacyTokens(ctx context.Context, tx *sql.Tx) ([]UserToken, error) {
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'user_tokens')`).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, nil
	}
	columns, err := legacyTokenColumns(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !columns["username"] || !columns["access_token"] {
		return nil, errors.New("legacy user_tokens table must contain username and access_token columns")
	}
	selectColumn := func(name string) string {
		if columns[name] {
			return name
		}
		return "NULL"
	}
	query := "SELECT username, access_token, " + selectColumn("refresh_token") + ", " + selectColumn("token_type") + ", " + selectColumn("expires_at") + ", " + selectColumn("created_at") + " FROM user_tokens"
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("read legacy token rows: %w", err)
	}
	defer rows.Close()
	var tokens []UserToken
	for rows.Next() {
		var token UserToken
		var access, refresh, tokenType sql.NullString
		var expires, created sql.NullTime
		if err := rows.Scan(&token.Username, &access, &refresh, &tokenType, &expires, &created); err != nil {
			return nil, err
		}
		if token.Username == "" || !access.Valid || access.String == "" {
			return nil, errors.New("legacy token row is missing username or access token")
		}
		token.AccessToken, token.RefreshToken, token.TokenType = access.String, refresh.String, tokenType.String
		if expires.Valid {
			token.ExpiresAt = expires.Time
		}
		if created.Valid {
			token.CreatedAt = created.Time
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func legacyTokenColumns(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(user_tokens)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue interface{}
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns[strings.ToLower(name)] = true
	}
	return columns, rows.Err()
}

func insertEncryptedMigrationToken(ctx context.Context, tx *sql.Tx, cipher *TokenCipher, token UserToken) error {
	access, err := cipher.Seal([]byte(token.AccessToken))
	if err != nil {
		return err
	}
	var refresh []byte
	if token.RefreshToken != "" {
		refresh, err = cipher.Seal([]byte(token.RefreshToken))
		if err != nil {
			return err
		}
	}
	if token.CreatedAt.IsZero() {
		token.CreatedAt = time.Now().UTC()
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO user_tokens_v2 (username, access_token_ciphertext, refresh_token_ciphertext, token_type, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`, token.Username, access, refresh, token.TokenType, nullableTime(token.ExpiresAt), token.CreatedAt)
	return err
}

func nullableTime(value time.Time) interface{} {
	if value.IsZero() {
		return nil
	}
	return value
}

func migrationOrganizationAuthorizers(ctx context.Context, tx *sql.Tx) (map[string][]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT organization_name, username FROM organization_hook_authorizers ORDER BY authorized_at, username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][]string)
	for rows.Next() {
		var organization, username string
		if err := rows.Scan(&organization, &username); err != nil {
			return nil, err
		}
		result[organization] = appendUnique(result[organization], strings.ToLower(username))
	}
	return result, rows.Err()
}

func discoverMigrationOrganizations(ctx context.Context, client migrationGiteaClient, users map[string]UserToken, retained map[string][]string) map[string][]string {
	organizations := make(map[string][]string, len(retained))
	for organization, usernames := range retained {
		organizations[organization] = append([]string(nil), usernames...)
	}
	for _, username := range sortedKeys(users) {
		names, err := client.organizations(ctx, users[username].AccessToken)
		if err != nil {
			continue
		}
		for _, organization := range names {
			organizations[organization] = appendUnique(organizations[organization], username)
		}
	}
	return organizations
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func rotateLegacyHooks(ctx context.Context, tx *sql.Tx, client migrationGiteaClient, config SecurityMigrationConfig, accessToken string, principal HookPrincipal) ([]legacyHookRollbackRecord, error) {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT rotate_legacy_hooks`); err != nil {
		return nil, err
	}
	hooks, err := client.hooks(ctx, accessToken, principal)
	if err != nil {
		_, _ = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT rotate_legacy_hooks`)
		_, _ = tx.ExecContext(ctx, `RELEASE SAVEPOINT rotate_legacy_hooks`)
		return nil, err
	}
	var records []legacyHookRollbackRecord
	fail := func(cause error) ([]legacyHookRollbackRecord, error) {
		_, localRollbackErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT rotate_legacy_hooks`)
		_, localReleaseErr := tx.ExecContext(ctx, `RELEASE SAVEPOINT rotate_legacy_hooks`)
		if rollbackErr := rollbackMigratedHooks(ctx, client, records, config.LegacyWebhookSecret); rollbackErr != nil {
			return nil, fmt.Errorf("%w; restore partially rotated hooks: %v; local rollback: %v", cause, rollbackErr, errors.Join(localRollbackErr, localReleaseErr))
		}
		if localRollbackErr != nil || localReleaseErr != nil {
			return nil, fmt.Errorf("%w; roll back local hook credentials: %v", cause, errors.Join(localRollbackErr, localReleaseErr))
		}
		return nil, cause
	}
	for _, hook := range hooks {
		if hook.Config.URL != config.WebhookURL || strings.HasPrefix(hook.AuthorizationHeader, "Gitea-Pages ") {
			continue
		}
		credential, err := createHookCredential(principal)
		if err != nil {
			return fail(err)
		}
		credential.GiteaHookID = hook.ID
		// Record the exact legacy state before PATCH. A connection can fail after
		// Gitea has applied the update, so an error response cannot prove that
		// no remote mutation occurred.
		record := legacyHookRollbackRecord{
			GiteaAPIURL: client.apiURL, AccessToken: accessToken, ScopeType: principal.ScopeType, ScopeName: principal.ScopeName,
			GiteaHookID: hook.ID, URL: hook.Config.URL, ContentType: hook.Config.ContentType, Events: hook.Events,
			Active: hook.Active, BranchFilter: hook.BranchFilter, AuthorizationHeader: hook.AuthorizationHeader,
		}
		records = append(records, record)
		if err := client.updateHook(ctx, accessToken, principal, hook.ID, secureHookPayload(config.WebhookURL, credential)); err != nil {
			return fail(err)
		}
		if err := insertMigrationHookCredential(ctx, tx, credential); err != nil {
			return fail(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT rotate_legacy_hooks`); err != nil {
		return nil, err
	}
	return records, nil
}

func secureHookPayload(webhookURL string, credential HookCredential) map[string]interface{} {
	return map[string]interface{}{
		"type": "gitea", "config": map[string]string{"url": webhookURL, "content_type": "json", "secret": string(credential.Secret)},
		"events": []string{"push", "delete"}, "active": true, "branch_filter": "gh-pages",
		"authorization_header": "Gitea-Pages " + base64.RawURLEncoding.EncodeToString([]byte(credential.Key)),
	}
}

func insertMigrationHookCredential(ctx context.Context, tx *sql.Tx, credential HookCredential) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO hook_credentials (hook_key, secret, principal_username, scope_type, scope_name, gitea_hook_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, credential.Key, credential.Secret, credential.PrincipalUsername, credential.ScopeType, credential.ScopeName, credential.GiteaHookID, time.Now().UTC())
	return err
}

func putMigrationOrganizationAuthorizer(ctx context.Context, tx *sql.Tx, organization, username string, hookID int64, principal HookPrincipal) error {
	var hookKey string
	if err := tx.QueryRowContext(ctx, `SELECT hook_key FROM hook_credentials WHERE gitea_hook_id = ? AND scope_type = ? AND scope_name = ?`, hookID, ScopeOrganization, principal.ScopeName).Scan(&hookKey); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO organization_hook_authorizers (organization_name, username, hook_key, authorized_at) VALUES (?, ?, ?, ?) ON CONFLICT(organization_name, username) DO UPDATE SET hook_key = excluded.hook_key, authorized_at = excluded.authorized_at`, organization, username, hookKey, time.Now().UTC())
	return err
}

func rollbackMigratedHooks(ctx context.Context, client migrationGiteaClient, hooks []legacyHookRollbackRecord, legacySecret []byte) error {
	var failures []error
	for index := len(hooks) - 1; index >= 0; index-- {
		if err := client.restoreLegacyHook(ctx, hooks[index], legacySecret); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func writeEncryptedMigrationManifest(path string, cipher *TokenCipher, manifest securityMigrationManifest) error {
	plaintext, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshal rollback manifest: %w", err)
	}
	sealed, err := cipher.Seal(plaintext)
	if err != nil {
		return fmt.Errorf("encrypt rollback manifest: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create rollback manifest: %w", err)
	}
	_, writeErr := file.Write([]byte(base64.RawStdEncoding.EncodeToString(sealed)))
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write rollback manifest: %w", writeErr)
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close rollback manifest: %w", closeErr)
	}
	return nil
}

// RestoreLegacyHooks restores every hook from the encrypted rollback manifest.
// It tries all recorded hooks so callers receive the complete manual-action
// list, and returns a non-nil error unless every PATCH succeeds.
func RestoreLegacyHooks(ctx context.Context, config LegacyHookRestoreConfig) error {
	if config.ManifestPath == "" || len(config.LegacyWebhookSecret) == 0 {
		return errors.New("--manifest and legacy webhook secret are required")
	}
	cipher, err := NewTokenCipher(config.TokenEncryptionKey)
	if err != nil {
		return err
	}
	manifest, err := readEncryptedMigrationManifest(config.ManifestPath, cipher)
	if err != nil {
		return err
	}
	client := migrationGiteaClient{httpClient: config.HTTPClient}
	if client.httpClient == nil {
		client.httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	var failures []error
	for _, hook := range manifest.Hooks {
		client.apiURL = hook.GiteaAPIURL
		if err := client.restoreLegacyHook(ctx, hook, config.LegacyWebhookSecret); err != nil {
			failures = append(failures, fmt.Errorf("restore %s hook %d: %w", hook.ScopeName, hook.GiteaHookID, err))
		}
	}
	return errors.Join(failures...)
}

func readEncryptedMigrationManifest(path string, cipher *TokenCipher) (securityMigrationManifest, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return securityMigrationManifest{}, fmt.Errorf("read rollback manifest: %w", err)
	}
	sealed, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return securityMigrationManifest{}, fmt.Errorf("decode rollback manifest: %w", err)
	}
	plaintext, err := cipher.Open(sealed)
	if err != nil {
		return securityMigrationManifest{}, fmt.Errorf("decrypt rollback manifest: %w", err)
	}
	var manifest securityMigrationManifest
	if err := json.Unmarshal(plaintext, &manifest); err != nil {
		return securityMigrationManifest{}, fmt.Errorf("parse rollback manifest: %w", err)
	}
	if manifest.Version != securityMigrationManifestVersion {
		return securityMigrationManifest{}, fmt.Errorf("unsupported rollback manifest version %d", manifest.Version)
	}
	return manifest, nil
}

type migrationGiteaClient struct {
	apiURL     string
	httpClient *http.Client
}

func (c migrationGiteaClient) organizations(ctx context.Context, token string) ([]string, error) {
	var result []string
	for page := 1; ; page++ {
		request, err := c.request(ctx, token, http.MethodGet, migrationPagePath("/api/v1/user/orgs", page), nil)
		if err != nil {
			return nil, err
		}
		response, err := c.httpClient.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode >= http.StatusBadRequest {
			apiErr := giteaHookError(response)
			response.Body.Close()
			return nil, apiErr
		}
		var organizations []struct {
			Username string `json:"username"`
			Name     string `json:"name"`
		}
		decodeErr := json.NewDecoder(response.Body).Decode(&organizations)
		response.Body.Close()
		if decodeErr != nil {
			return nil, decodeErr
		}
		if len(organizations) == 0 {
			return result, nil
		}
		for _, organization := range organizations {
			name := organization.Username
			if name == "" {
				name = organization.Name
			}
			if name != "" {
				result = appendUnique(result, name)
			}
		}
	}
}

func (c migrationGiteaClient) hooks(ctx context.Context, token string, principal HookPrincipal) ([]webhookInfo, error) {
	var result []webhookInfo
	for page := 1; ; page++ {
		request, err := c.request(ctx, token, http.MethodGet, migrationPagePath(c.hookPath(principal, 0), page), nil)
		if err != nil {
			return nil, err
		}
		response, err := c.httpClient.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode >= http.StatusBadRequest {
			apiErr := giteaHookError(response)
			response.Body.Close()
			return nil, apiErr
		}
		var hooks []webhookInfo
		decodeErr := json.NewDecoder(response.Body).Decode(&hooks)
		response.Body.Close()
		if decodeErr != nil {
			return nil, decodeErr
		}
		if len(hooks) == 0 {
			return result, nil
		}
		result = append(result, hooks...)
	}
}

func migrationPagePath(path string, page int) string {
	return fmt.Sprintf("%s?page=%d&limit=%d", path, page, migrationGiteaPageLimit)
}

func (c migrationGiteaClient) updateHook(ctx context.Context, token string, principal HookPrincipal, hookID int64, payload map[string]interface{}) error {
	request, err := c.request(ctx, token, http.MethodPatch, c.hookPath(principal, hookID), payload)
	if err != nil {
		return err
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		return giteaHookError(response)
	}
	return nil
}

func (c migrationGiteaClient) restoreLegacyHook(ctx context.Context, hook legacyHookRollbackRecord, secret []byte) error {
	principal := HookPrincipal{ScopeType: hook.ScopeType, ScopeName: hook.ScopeName}
	payload := map[string]interface{}{
		"type": "gitea", "config": map[string]string{"url": hook.URL, "content_type": hook.ContentType, "secret": string(secret)},
		"events": hook.Events, "active": hook.Active, "branch_filter": hook.BranchFilter, "authorization_header": hook.AuthorizationHeader,
	}
	return c.updateHook(ctx, hook.AccessToken, principal, hook.GiteaHookID, payload)
}

func (c migrationGiteaClient) request(ctx context.Context, token, method, path string, payload map[string]interface{}) (*http.Request, error) {
	endpoint, err := url.Parse(strings.TrimSuffix(c.apiURL, "/") + path)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(string(encoded))
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func (c migrationGiteaClient) hookPath(principal HookPrincipal, hookID int64) string {
	path := "/api/v1/user/hooks"
	if principal.ScopeType == ScopeOrganization {
		path = "/api/v1/orgs/" + url.PathEscape(principal.ScopeName) + "/hooks"
	}
	if hookID > 0 {
		path += fmt.Sprintf("/%d", hookID)
	}
	return path
}

func logMigrationOrganizationManualAction(organization string, cause error) {
	// This exact organization name is deliberately emitted for the operator's
	// reauthorization runbook; only real Gitea/token/scope/admin failures reach
	// this branch.
	fmt.Fprintf(os.Stderr, "organization %s was not migrated and requires manual reauthorization: %v\n", organization, cause)
}

// runSecurityMigrationCommand handles only offline maintenance commands. Its
// boolean result lets main keep the normal HTTP-server startup path unchanged.
func runSecurityMigrationCommand(args []string) (handled bool, err error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "migrate-security":
		flags := flag.NewFlagSet("migrate-security", flag.ContinueOnError)
		backup := flags.String("backup", "", "existing mode-0600 tokens.db backup")
		manifest := flags.String("manifest", "", "new encrypted rollback manifest path")
		database := flags.String("database", filepath.Join(getEnvOrDefault("DEPLOYER_DATA_DIR", "/var/lib/deployer"), "tokens.db"), "tokens.db path")
		skipOrganizations := flags.Bool("skip-failed-organizations", false, "continue only after named organization hook failures")
		if err := flags.Parse(args[1:]); err != nil {
			return true, err
		}
		key, legacySecret, err := migrationCLISecrets()
		if err != nil {
			return true, err
		}
		return true, RunSecurityMigration(context.Background(), SecurityMigrationConfig{
			DatabasePath: *database, BackupPath: *backup, ManifestPath: *manifest, TokenEncryptionKey: key,
			LegacyWebhookSecret: legacySecret, GiteaAPIURL: os.Getenv("GITEA_API_URL"), WebhookURL: os.Getenv("WEBHOOK_PUBLIC_URL"),
			SkipFailedOrganizations: *skipOrganizations,
		})
	case "restore-legacy-hooks":
		flags := flag.NewFlagSet("restore-legacy-hooks", flag.ContinueOnError)
		manifest := flags.String("manifest", "", "encrypted rollback manifest path")
		if err := flags.Parse(args[1:]); err != nil {
			return true, err
		}
		key, legacySecret, err := migrationCLISecrets()
		if err != nil {
			return true, err
		}
		return true, RestoreLegacyHooks(context.Background(), LegacyHookRestoreConfig{ManifestPath: *manifest, TokenEncryptionKey: key, LegacyWebhookSecret: legacySecret})
	default:
		return false, nil
	}
}

func migrationCLISecrets() ([]byte, []byte, error) {
	keyPath := os.Getenv("TOKEN_ENCRYPTION_KEY_FILE")
	if keyPath == "" {
		return nil, nil, errors.New("TOKEN_ENCRYPTION_KEY_FILE is required for security migration")
	}
	key, err := readSecretFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("TOKEN_ENCRYPTION_KEY_FILE: %w", err)
	}
	if len(key) != 32 {
		return nil, nil, errors.New("TOKEN_ENCRYPTION_KEY_FILE must contain exactly 32 bytes")
	}
	legacyPath := os.Getenv("LEGACY_WEBHOOK_SECRET_FILE")
	if legacyPath == "" {
		return nil, nil, errors.New("LEGACY_WEBHOOK_SECRET_FILE is required for security migration")
	}
	legacySecret, err := readSecretFile(legacyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("LEGACY_WEBHOOK_SECRET_FILE: %w", err)
	}
	return key, legacySecret, nil
}
