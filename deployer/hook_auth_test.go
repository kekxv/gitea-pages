package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
	"time"
)

// These tests fail if authentication ever verifies a delivery with a secret
// selected from attacker-controlled request contents rather than its hook key.
func TestAuthenticateWebhookRejectsAttackerSecretForVictimKey(t *testing.T) {
	store := newMemoryHookStore(t)
	if err := store.PutHook(context.Background(), HookCredential{Key: "victim-key", Secret: []byte("victim-secret"), PrincipalUsername: "victim", ScopeType: ScopeUser, ScopeName: "victim"}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"repository":{"id":42}}`)
	req := signedHookRequest(body, "victim-key", []byte("attacker-secret"), "delivery-1")
	if _, err := AuthenticateWebhook(context.Background(), req, store); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

// This test fails if a valid delivery can be accepted again for the same hook.
func TestAuthenticateWebhookRejectsReplay(t *testing.T) {
	store := newMemoryHookStore(t)
	cred := HookCredential{Key: "key-1", Secret: []byte("secret-1"), PrincipalUsername: "alice", ScopeType: ScopeUser, ScopeName: "alice"}
	if err := store.PutHook(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	req1 := signedHookRequest([]byte(`{}`), cred.Key, cred.Secret, "delivery-1")
	req2 := signedHookRequest([]byte(`{}`), cred.Key, cred.Secret, "delivery-1")
	if _, err := AuthenticateWebhook(context.Background(), req1, store); err != nil {
		t.Fatal(err)
	}
	if _, err := AuthenticateWebhook(context.Background(), req2, store); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected replay rejection, got %v", err)
	}
}

func TestAuthenticateWebhookReturnsVerifiedHookPrincipalAndBody(t *testing.T) {
	store := newMemoryHookStore(t)
	credential := HookCredential{Key: "org-hook", Secret: []byte("secret-1"), PrincipalUsername: "alice", ScopeType: ScopeOrganization, ScopeName: "platform"}
	if err := store.PutHook(context.Background(), credential); err != nil {
		t.Fatal(err)
	}

	result, err := AuthenticateWebhook(context.Background(), signedHookRequest([]byte(`{"event":"push"}`), credential.Key, credential.Secret, "delivery-1"), store)
	if err != nil {
		t.Fatalf("authenticate webhook: %v", err)
	}
	if got, want := string(result.Body), `{"event":"push"}`; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if got, want := result.HookKey, "org-hook"; got != want {
		t.Errorf("hook key = %q, want %q", got, want)
	}
	if got, want := result.DeliveryID, "delivery-1"; got != want {
		t.Errorf("delivery ID = %q, want %q", got, want)
	}
	if got, want := result.Principal, (HookPrincipal{Username: "alice", ScopeType: ScopeOrganization, ScopeName: "platform"}); got != want {
		t.Errorf("principal = %#v, want %#v", got, want)
	}
}

func TestAuthenticateWebhookRejectsMalformedOrIncompleteAuthentication(t *testing.T) {
	store := newMemoryHookStore(t)
	credential := HookCredential{Key: "key-1", Secret: []byte("secret-1"), PrincipalUsername: "alice", ScopeType: ScopeUser, ScopeName: "alice"}
	if err := store.PutHook(context.Background(), credential); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{
			name: "bearer JSON identity",
			mutate: func(request *http.Request) {
				request.Header.Set("Authorization", "Bearer eyJ1c2VybmFtZSI6ImFsaWNlIn0")
			},
		},
		{
			name: "missing delivery ID",
			mutate: func(request *http.Request) {
				request.Header.Del("X-Gitea-Delivery")
			},
		},
		{
			name: "missing signature",
			mutate: func(request *http.Request) {
				request.Header.Del("X-Gitea-Signature")
			},
		},
		{
			name: "unknown hook key",
			mutate: func(request *http.Request) {
				request.Header.Set("Authorization", "Gitea-Pages "+base64.RawURLEncoding.EncodeToString([]byte("unknown")))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := signedHookRequest([]byte(`{}`), credential.Key, credential.Secret, t.Name())
			test.mutate(request)
			if _, err := AuthenticateWebhook(context.Background(), request, store); err == nil {
				t.Fatal("expected authentication rejection")
			}
		})
	}
}

func TestAuthenticateWebhookRejectsBodiesOverOneMiB(t *testing.T) {
	store := newMemoryHookStore(t)
	credential := HookCredential{Key: "key-1", Secret: []byte("secret-1"), PrincipalUsername: "alice", ScopeType: ScopeUser, ScopeName: "alice"}
	if err := store.PutHook(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("a"), (1<<20)+1)
	request := signedHookRequest(body, credential.Key, credential.Secret, "delivery-1")
	if _, err := AuthenticateWebhook(context.Background(), request, store); err == nil {
		t.Fatal("expected oversized body rejection")
	}
}

func TestHookStorePersistsCredentialsAndRejectsDuplicateDeliveries(t *testing.T) {
	dataDir := t.TempDir()
	store := NewTokenStore(dataDir)
	if store.db == nil {
		t.Fatal("token store did not initialize its SQLite database")
	}
	credential := HookCredential{Key: "key-1", Secret: []byte("secret-1"), PrincipalUsername: "alice", ScopeType: ScopeOrganization, ScopeName: "platform", GiteaHookID: 42}
	if err := store.PutHook(context.Background(), credential); err != nil {
		t.Fatalf("put hook: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}

	reloaded := NewTokenStore(dataDir)
	t.Cleanup(func() { _ = reloaded.Close() })
	stored, err := reloaded.GetHook(context.Background(), credential.Key)
	if err != nil {
		t.Fatalf("get hook: %v", err)
	}
	if stored == nil {
		t.Fatal("hook credential was not persisted")
	}
	if got, want := *stored, credential; got.Key != want.Key || !bytes.Equal(got.Secret, want.Secret) || got.Principal() != want.Principal() || got.GiteaHookID != want.GiteaHookID {
		t.Fatalf("stored credential = %#v, want %#v", got, want)
	}
	if inserted, err := reloaded.RecordDelivery(context.Background(), credential.Key, "delivery-1", time.Now()); err != nil || !inserted {
		t.Fatalf("first delivery = (%v, %v), want (true, nil)", inserted, err)
	}
	if inserted, err := reloaded.RecordDelivery(context.Background(), credential.Key, "delivery-1", time.Now()); err != nil || inserted {
		t.Fatalf("duplicate delivery = (%v, %v), want (false, nil)", inserted, err)
	}
}

func TestHookStoreCleansDeliveriesOlderThanSevenDaysAtStartup(t *testing.T) {
	dataDir := t.TempDir()
	store := NewTokenStore(dataDir)
	if store.db == nil {
		t.Fatal("token store did not initialize its SQLite database")
	}
	if _, err := store.db.Exec(`INSERT INTO webhook_deliveries (hook_key, delivery_id, received_at) VALUES (?, ?, ?)`, "key-1", "old", time.Now().Add(-8*24*time.Hour)); err != nil {
		t.Fatalf("seed old delivery: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}

	reloaded := NewTokenStore(dataDir)
	t.Cleanup(func() { _ = reloaded.Close() })
	var count int
	if err := reloaded.db.QueryRow(`SELECT COUNT(*) FROM webhook_deliveries WHERE delivery_id = 'old'`).Scan(&count); err != nil {
		t.Fatalf("count old deliveries: %v", err)
	}
	if count != 0 {
		t.Fatalf("old delivery count = %d, want 0", count)
	}
}

func newMemoryHookStore(t *testing.T) *TokenStore {
	t.Helper()
	store := NewTokenStore(t.TempDir())
	if store.db == nil {
		t.Fatal("token store did not initialize its SQLite database")
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func signedHookRequest(body []byte, key string, secret []byte, deliveryID string) *http.Request {
	request, _ := http.NewRequest(http.MethodPost, "http://example.test/webhook", bytes.NewReader(body))
	request.Header.Set("Authorization", "Gitea-Pages "+base64.RawURLEncoding.EncodeToString([]byte(key)))
	request.Header.Set("X-Gitea-Delivery", deliveryID)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	request.Header.Set("X-Gitea-Signature", hex.EncodeToString(mac.Sum(nil)))
	return request
}
