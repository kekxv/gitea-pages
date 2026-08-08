package main

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenCipherDoesNotPersistPlaintext(t *testing.T) {
	cipher := mustTokenCipher(t, bytes.Repeat([]byte{1}, 32))
	sealed, err := cipher.Seal([]byte("access-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("access-secret")) {
		t.Fatal("ciphertext contains plaintext")
	}
	plain, err := cipher.Open(sealed)
	if err != nil || string(plain) != "access-secret" {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestTokenCipherReturnsDecryptErrorForTamperedCiphertext(t *testing.T) {
	cipher := mustTokenCipher(t, bytes.Repeat([]byte{1}, 32))
	sealed, err := cipher.Seal([]byte("access-secret"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 1

	if _, err := cipher.Open(sealed); !errors.Is(err, ErrTokenDecrypt) {
		t.Fatalf("Open() error = %v, want ErrTokenDecrypt", err)
	}
}

func mustTokenCipher(t *testing.T, key []byte) *TokenCipher {
	t.Helper()
	cipher, err := NewTokenCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func TestTokenStoreGetReturnsCopy(t *testing.T) {
	store := newTestTokenStore(t)
	store.Set("alice", &UserToken{AccessToken: "original"})

	got := store.Get("alice")
	got.AccessToken = "modified"

	if got := store.Get("alice").AccessToken; got != "original" {
		t.Fatalf("store leaked mutable pointer: %s", got)
	}
}

func TestTokenStorePersistsEncryptedTokens(t *testing.T) {
	dataDir := t.TempDir()
	key := bytes.Repeat([]byte{2}, 32)
	store, err := NewTokenStore(dataDir, key)
	if err != nil {
		t.Fatalf("NewTokenStore() error = %v", err)
	}
	store.Set("alice", &UserToken{AccessToken: "fixture-access-token", RefreshToken: "fixture-refresh-token"})
	if err := store.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dataDir, "tokens.db"))
	if err != nil {
		t.Fatalf("read token database: %v", err)
	}
	if bytes.Contains(raw, []byte("fixture-access-token")) || bytes.Contains(raw, []byte("fixture-refresh-token")) {
		t.Fatal("token database contains plaintext fixture token")
	}

	reloaded, err := NewTokenStore(dataDir, key)
	if err != nil {
		t.Fatalf("reload token store: %v", err)
	}
	t.Cleanup(func() { _ = reloaded.Close() })
	got := reloaded.Get("alice")
	if got == nil || got.AccessToken != "fixture-access-token" || got.RefreshToken != "fixture-refresh-token" {
		t.Fatalf("reloaded token = %#v", got)
	}
}

func TestTokenStoreRefusesPlaintextTokenRows(t *testing.T) {
	dataDir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE user_tokens (username TEXT PRIMARY KEY, access_token TEXT NOT NULL); INSERT INTO user_tokens (username, access_token) VALUES ('alice', 'plaintext-access-token')`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewTokenStore(dataDir, bytes.Repeat([]byte{3}, 32))
	if err == nil {
		_ = store.Close()
		t.Fatal("NewTokenStore accepted plaintext token rows")
	}
	if !strings.Contains(err.Error(), "Task 10") {
		t.Fatalf("NewTokenStore() error = %q, want Task 10 migration instruction", err)
	}

	check, err := sql.Open("sqlite", filepath.Join(dataDir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var migratedTable int
	if err := check.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'user_tokens_v2')`).Scan(&migratedTable); err != nil {
		t.Fatal(err)
	}
	if migratedTable != 0 {
		t.Fatal("legacy-token refusal committed a partial schema migration")
	}
}

func TestTokenStoreUpdateTokenPersistsRefreshedToken(t *testing.T) {
	dataDir := t.TempDir()
	key := bytes.Repeat([]byte{4}, 32)
	store, err := NewTokenStore(dataDir, key)
	if err != nil {
		t.Fatal(err)
	}
	store.Set("alice", &UserToken{AccessToken: "old-access", RefreshToken: "old-refresh"})
	if err := store.UpdateToken("alice", func(token UserToken) UserToken {
		token.AccessToken = "new-access"
		return token
	}); err != nil {
		t.Fatalf("UpdateToken() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewTokenStore(dataDir, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reloaded.Close() })
	if got := reloaded.Get("alice"); got == nil || got.AccessToken != "new-access" || got.RefreshToken != "old-refresh" {
		t.Fatalf("updated token = %#v", got)
	}
}

func newTestTokenStore(t *testing.T) *TokenStore {
	t.Helper()
	return newTestTokenStoreAt(t, t.TempDir())
}

func newTestTokenStoreAt(t *testing.T, dataDir string) *TokenStore {
	t.Helper()
	store, err := NewTokenStore(dataDir, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
