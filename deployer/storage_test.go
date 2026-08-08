package main

import "testing"

func TestTokenStorePersistsTokens(t *testing.T) {
	dataDir := t.TempDir()

	store := newTestTokenStoreAt(t, dataDir)
	if store.db == nil {
		t.Fatal("token store did not initialize its SQLite database")
	}
	store.Set("alice", &UserToken{AccessToken: "access-token", RefreshToken: "refresh-token"})
	if err := store.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}

	reloaded := newTestTokenStoreAt(t, dataDir)
	t.Cleanup(func() { _ = reloaded.Close() })
	if reloaded.db == nil {
		t.Fatal("reloaded token store did not initialize its SQLite database")
	}

	token := reloaded.Get("alice")
	if token == nil {
		t.Fatal("persisted token was not reloaded")
	}
	if token.AccessToken != "access-token" || token.RefreshToken != "refresh-token" {
		t.Fatalf("unexpected reloaded token: %#v", token)
	}
}
