package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestMigrationRollsBackDatabaseWhenUserHookRotationFails(t *testing.T) {
	server := newMigrationGiteaServer(t, true, false)
	config := seedLegacyMigration(t, server.URL)

	err := RunSecurityMigration(context.Background(), config)
	if err == nil {
		t.Fatal("expected migration failure")
	}
	assertLegacyTokenRowExists(t, config.DatabasePath, "alice")
	assertNoHookCredentialRows(t, config.DatabasePath)
}

func TestMigrationEncryptsTokensRotatesUserAndOrganizationHooksAndHidesSecrets(t *testing.T) {
	server := newMigrationGiteaServer(t, false, false)
	config := seedLegacyMigration(t, server.URL)

	if err := RunSecurityMigration(context.Background(), config); err != nil {
		t.Fatalf("RunSecurityMigration() error = %v", err)
	}

	check, err := sql.Open("sqlite", config.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var encryptedRows, hooks, legacyRows int
	if err := check.QueryRow(`SELECT COUNT(*) FROM user_tokens_v2`).Scan(&encryptedRows); err != nil {
		t.Fatal(err)
	}
	if err := check.QueryRow(`SELECT COUNT(*) FROM hook_credentials`).Scan(&hooks); err != nil {
		t.Fatal(err)
	}
	if err := check.QueryRow(`SELECT COUNT(*) FROM user_tokens`).Scan(&legacyRows); err == nil || !strings.Contains(err.Error(), "no such table") {
		t.Fatalf("legacy user_tokens still available or unexpected error: %v", err)
	}
	if encryptedRows != 1 || hooks != 2 {
		t.Fatalf("encrypted rows/hooks = %d/%d, want 1/2", encryptedRows, hooks)
	}
	manifest, err := os.ReadFile(config.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(manifest, []byte("plain-access-token")) || bytes.Contains(manifest, []byte("legacy-webhook-secret")) {
		t.Fatal("rollback manifest contains plaintext secret")
	}
	if info, err := os.Stat(config.ManifestPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("manifest permissions = %v, %v; want 0600", info.Mode(), err)
	}
}

func TestMigrationRequiresProtectedExistingBackup(t *testing.T) {
	server := newMigrationGiteaServer(t, false, false)
	config := seedLegacyMigration(t, server.URL)
	if err := os.Chmod(config.BackupPath, 0644); err != nil {
		t.Fatal(err)
	}

	if err := RunSecurityMigration(context.Background(), config); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("RunSecurityMigration() error = %v, want backup mode rejection", err)
	}
	assertLegacyTokenRowExists(t, config.DatabasePath, "alice")
}

func TestMigrationPreservesLegacyRowsWhenOptionalTokenColumnsAreAbsent(t *testing.T) {
	server := newMigrationGiteaServer(t, false, false)
	config := seedLegacyMigration(t, server.URL)
	db, err := sql.Open("sqlite", config.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE user_tokens; CREATE TABLE user_tokens (username TEXT PRIMARY KEY, access_token TEXT NOT NULL); INSERT INTO user_tokens (username, access_token) VALUES ('alice', 'plain-access-token')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if err := RunSecurityMigration(context.Background(), config); err != nil {
		t.Fatalf("RunSecurityMigration() error = %v", err)
	}
	store, err := NewTokenStore(filepath.Dir(config.DatabasePath), config.TokenEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if token := store.Get("alice"); token == nil || token.AccessToken != "plain-access-token" || token.RefreshToken != "" {
		t.Fatalf("migrated minimal-schema token = %#v", token)
	}
}

func TestMigrationCanSkipFailedOrganizationButNamesIt(t *testing.T) {
	server := newMigrationGiteaServer(t, false, true)
	config := seedLegacyMigration(t, server.URL)
	config.SkipFailedOrganizations = true

	if err := RunSecurityMigration(context.Background(), config); err != nil {
		t.Fatalf("RunSecurityMigration() error = %v", err)
	}
	check, err := sql.Open("sqlite", config.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var hooks int
	if err := check.QueryRow(`SELECT COUNT(*) FROM hook_credentials`).Scan(&hooks); err != nil {
		t.Fatal(err)
	}
	if hooks != 1 {
		t.Fatalf("migrated hooks = %d, want user hook only", hooks)
	}
}

func TestMigrationPaginatesUserOrganizationAndHookLists(t *testing.T) {
	server := newPaginatedMigrationGiteaServer(t)
	config := seedLegacyMigration(t, server.URL)

	if err := RunSecurityMigration(context.Background(), config); err != nil {
		t.Fatalf("RunSecurityMigration() error = %v", err)
	}
	assertHookCredentialCount(t, config.DatabasePath, 5)
	for _, path := range []string{
		"/api/v1/user/hooks/12",
		"/api/v1/orgs/engineering/hooks/22",
		"/api/v1/orgs/operations/hooks/31",
	} {
		if _, ok := server.patch(path); !ok {
			t.Errorf("page-two hook %s was not rotated", path)
		}
	}
}

func TestMigrationRestoresHookAfterAmbiguousPatchFailure(t *testing.T) {
	server := newMigrationGiteaServer(t, false, false)
	server.disconnectNextUserPatch = true
	config := seedLegacyMigration(t, server.URL)

	if err := RunSecurityMigration(context.Background(), config); err == nil {
		t.Fatal("expected migration failure after disconnected PATCH")
	}
	assertLegacyTokenRowExists(t, config.DatabasePath, "alice")
	payload, ok := server.patch("/api/v1/user/hooks/11")
	if !ok {
		t.Fatal("migration did not attempt the user hook PATCH")
	}
	if got := payload.Config["secret"]; got != "legacy-webhook-secret" {
		t.Fatalf("ambiguous PATCH left hook secret = %q, want restored legacy secret", got)
	}
	if got := payload.AuthorizationHeader; got != "Bearer legacy-user" {
		t.Fatalf("ambiguous PATCH left authorization = %q, want restored legacy header", got)
	}
}

func TestRestoreLegacyHooksReadsEncryptedManifestAndRestoresLegacyCredential(t *testing.T) {
	server := newMigrationGiteaServer(t, false, false)
	config := seedLegacyMigration(t, server.URL)
	if err := RunSecurityMigration(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	err := RestoreLegacyHooks(context.Background(), LegacyHookRestoreConfig{
		ManifestPath:        config.ManifestPath,
		TokenEncryptionKey:  config.TokenEncryptionKey,
		LegacyWebhookSecret: config.LegacyWebhookSecret,
	})
	if err != nil {
		t.Fatalf("RestoreLegacyHooks() error = %v", err)
	}
	for path, wantAuthorization := range map[string]string{
		"/api/v1/user/hooks/11":             "Bearer legacy-user",
		"/api/v1/orgs/engineering/hooks/22": "Bearer legacy-org",
	} {
		payload, ok := server.patch(path)
		if !ok {
			t.Fatalf("restore did not PATCH %s", path)
		}
		if got := payload.Config["secret"]; got != "legacy-webhook-secret" {
			t.Errorf("restored secret for %s = %q, want legacy secret", path, got)
		}
		if got := payload.AuthorizationHeader; got != wantAuthorization {
			t.Errorf("restored authorization header for %s = %q, want %q", path, got, wantAuthorization)
		}
	}
}

func seedLegacyMigration(t *testing.T, apiURL string) SecurityMigrationConfig {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tokens.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE user_tokens (username TEXT PRIMARY KEY, access_token TEXT NOT NULL, refresh_token TEXT, token_type TEXT, expires_at DATETIME, created_at DATETIME); INSERT INTO user_tokens (username, access_token, refresh_token, token_type) VALUES ('alice', 'plain-access-token', 'plain-refresh-token', 'Bearer')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(dir, "tokens.db.backup")
	if err := os.WriteFile(backupPath, []byte("backup already created by operator"), 0600); err != nil {
		t.Fatal(err)
	}
	return SecurityMigrationConfig{
		DatabasePath:        dbPath,
		BackupPath:          backupPath,
		ManifestPath:        filepath.Join(dir, "legacy-hooks.manifest"),
		TokenEncryptionKey:  bytes.Repeat([]byte("k"), 32),
		LegacyWebhookSecret: []byte("legacy-webhook-secret"),
		GiteaAPIURL:         apiURL,
		WebhookURL:          "https://pages.example.com/webhook",
	}
}

func assertLegacyTokenRowExists(t *testing.T, dbPath, username string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_tokens WHERE username = ?`, username).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("legacy token rows = %d, want 1", count)
	}
}

func assertNoHookCredentialRows(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var exists int
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'hook_credentials')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != 0 {
		t.Fatal("hook credential schema was committed")
	}
}

func assertHookCredentialCount(t *testing.T, dbPath string, want int) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM hook_credentials`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("hook credential rows = %d, want %d", count, want)
	}
}

type migrationGiteaServer struct {
	*httptest.Server
	mu                      sync.Mutex
	patches                 map[string]migrationHookPatch
	disconnectNextUserPatch bool
}

type migrationHookPatch struct {
	Config              map[string]string `json:"config"`
	AuthorizationHeader string            `json:"authorization_header"`
}

func (s *migrationGiteaServer) patch(path string) (migrationHookPatch, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	patch, ok := s.patches[path]
	return patch, ok
}

func (s *migrationGiteaServer) takeUserPatchDisconnect() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.disconnectNextUserPatch {
		return false
	}
	s.disconnectNextUserPatch = false
	return true
}

func newMigrationGiteaServer(t *testing.T, failUserPatch, failOrganizationPatch bool) *migrationGiteaServer {
	t.Helper()
	server := &migrationGiteaServer{patches: make(map[string]migrationHookPatch)}
	t.Cleanup(func() { server.Close() })
	legacyHook := func(id int64, authorizationHeader string) webhookInfo {
		return webhookInfo{ID: id, Type: "gitea", Config: webhookConfig{URL: "https://pages.example.com/webhook", ContentType: "json", Secret: "legacy-webhook-secret"}, Events: []string{"push", "delete"}, Active: true, BranchFilter: "gh-pages", AuthorizationHeader: authorizationHeader}
	}
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user/hooks":
			if page != "" && page != "1" {
				_ = json.NewEncoder(w).Encode([]webhookInfo{})
				return
			}
			_ = json.NewEncoder(w).Encode([]webhookInfo{legacyHook(11, "Bearer legacy-user")})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user/orgs":
			if page != "" && page != "1" {
				_ = json.NewEncoder(w).Encode([]map[string]string{})
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]string{{"username": "engineering"}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/orgs/engineering/hooks":
			if page != "" && page != "1" {
				_ = json.NewEncoder(w).Encode([]webhookInfo{})
				return
			}
			_ = json.NewEncoder(w).Encode([]webhookInfo{legacyHook(22, "Bearer legacy-org")})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/user/hooks/11":
			if failUserPatch {
				http.Error(w, "user hook update denied", http.StatusForbidden)
				return
			}
			server.recordPatch(t, r)
			if server.takeUserPatchDisconnect() {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack ambiguous PATCH connection: %v", err)
					return
				}
				_ = connection.Close()
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/orgs/engineering/hooks/22":
			if failOrganizationPatch {
				http.Error(w, "organization hook update denied", http.StatusForbidden)
				return
			}
			server.recordPatch(t, r)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}

func newPaginatedMigrationGiteaServer(t *testing.T) *migrationGiteaServer {
	t.Helper()
	server := &migrationGiteaServer{patches: make(map[string]migrationHookPatch)}
	t.Cleanup(func() { server.Close() })
	legacyHook := func(id int64, authorizationHeader string) webhookInfo {
		return webhookInfo{ID: id, Type: "gitea", Config: webhookConfig{URL: "https://pages.example.com/webhook", ContentType: "json", Secret: "legacy-webhook-secret"}, Events: []string{"push", "delete"}, Active: true, BranchFilter: "gh-pages", AuthorizationHeader: authorizationHeader}
	}
	page := func(request *http.Request) string {
		if value := request.URL.Query().Get("page"); value != "" {
			return value
		}
		return "1"
	}
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user/hooks":
			switch page(r) {
			case "1":
				_ = json.NewEncoder(w).Encode([]webhookInfo{legacyHook(11, "Bearer legacy-user")})
			case "2":
				_ = json.NewEncoder(w).Encode([]webhookInfo{legacyHook(12, "Bearer legacy-user")})
			default:
				_ = json.NewEncoder(w).Encode([]webhookInfo{})
			}
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user/orgs":
			switch page(r) {
			case "1":
				_ = json.NewEncoder(w).Encode([]map[string]string{{"username": "engineering"}})
			case "2":
				_ = json.NewEncoder(w).Encode([]map[string]string{{"username": "operations"}})
			default:
				_ = json.NewEncoder(w).Encode([]map[string]string{})
			}
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/orgs/engineering/hooks":
			switch page(r) {
			case "1":
				_ = json.NewEncoder(w).Encode([]webhookInfo{legacyHook(21, "Bearer legacy-engineering")})
			case "2":
				_ = json.NewEncoder(w).Encode([]webhookInfo{legacyHook(22, "Bearer legacy-engineering")})
			default:
				_ = json.NewEncoder(w).Encode([]webhookInfo{})
			}
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/orgs/operations/hooks":
			switch page(r) {
			case "1":
				_ = json.NewEncoder(w).Encode([]webhookInfo{legacyHook(31, "Bearer legacy-operations")})
			default:
				_ = json.NewEncoder(w).Encode([]webhookInfo{})
			}
		case r.Method == http.MethodPatch:
			server.recordPatch(t, r)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}

func (s *migrationGiteaServer) recordPatch(t *testing.T, request *http.Request) {
	t.Helper()
	var payload migrationHookPatch
	if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
		t.Errorf("decode PATCH payload: %v", err)
		return
	}
	s.mu.Lock()
	s.patches[request.URL.Path] = payload
	s.mu.Unlock()
}
