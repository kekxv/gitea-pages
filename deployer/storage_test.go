package main

import (
	"context"
	"testing"
)

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

// This test fails if upgrading leaves existing organization hook credentials
// without the administrator association needed to verify later deliveries.
func TestTokenStoreBackfillsOrganizationHookAuthorizerOnStartup(t *testing.T) {
	dataDir := t.TempDir()

	store := newTestTokenStoreAt(t, dataDir)
	store.Set("caesar", &UserToken{AccessToken: "access-token"})
	if err := store.PutHook(context.Background(), HookCredential{
		Key:               "legacy-org-hook",
		Secret:            []byte("secret"),
		PrincipalUsername: "caesar",
		ScopeType:         ScopeOrganization,
		ScopeName:         "bcr",
	}); err != nil {
		t.Fatalf("store legacy organization hook: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}

	reloaded := newTestTokenStoreAt(t, dataDir)
	t.Cleanup(func() { _ = reloaded.Close() })
	authorizers, err := reloaded.OrganizationHookAuthorizers(context.Background(), "bcr")
	if err != nil {
		t.Fatalf("load organization hook authorizers: %v", err)
	}
	if len(authorizers) != 1 || authorizers[0] != "caesar" {
		t.Fatalf("organization hook authorizers = %#v, want [caesar]", authorizers)
	}
}
