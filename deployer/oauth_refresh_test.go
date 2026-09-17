package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefreshAllTokensKeepsTokenWithOneHourRemaining(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("token with an hour remaining should not be refreshed yet")
		w.Write([]byte(`{"access_token":"new","expires_in":3600}`))
	}))
	defer server.Close()
	store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Set("caesar", &UserToken{AccessToken: "old", RefreshToken: "refresh", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	h := NewOAuthHandler(&OAuthConfig{TokenURL: server.URL}, store, "", "")
	h.RefreshAllTokens()
	if got := store.Get("caesar").AccessToken; got != "old" {
		t.Fatalf("unexpected token replacement: %s", got)
	}
}

func TestTokenRefreshFailurePreservesStoredGrant(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		expiry    time.Duration
		wantToken string
		wantError string
	}{
		{"rejected", 400, `{"error":"invalid_grant","error_description":"private-detail"}`, -time.Hour, "", "invalid_grant"},
		{"upstream unavailable", 503, `private-detail`, -time.Hour, "", "503"},
		{"empty access token", 200, `{"expires_in":3600}`, -time.Hour, "", "invalid token refresh response"},
		{"negative expiry", 200, `{"access_token":"new","expires_in":-1}`, -time.Hour, "", "invalid token refresh response"},
		{"still valid during outage", 503, `private-detail`, 4 * time.Minute, "old", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte("k"), 32))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.Set("caesar", &UserToken{AccessToken: "old", RefreshToken: "refresh", ExpiresAt: time.Now().Add(tc.expiry)}); err != nil {
				t.Fatal(err)
			}
			h := NewOAuthHandler(&OAuthConfig{TokenURL: server.URL}, store, "", "")
			got, err := h.usableAccessToken("Caesar")
			if got != tc.wantToken {
				t.Errorf("token = %q, want %q", got, tc.wantToken)
			}
			if tc.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) || strings.Contains(err.Error(), "private-detail") {
				t.Errorf("unexpected or unsafe refresh error: %v", err)
			}
			stored := store.Get("caesar")
			if stored.AccessToken != "old" || stored.RefreshToken != "refresh" {
				t.Error("failed refresh overwrote saved grant")
			}
		})
	}
}

func TestRefreshAllTokensRenewsBeforeExpiry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"new","expires_in":3600}`)
	}))
	defer server.Close()
	store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Set("caesar", &UserToken{AccessToken: "old", RefreshToken: "refresh", ExpiresAt: time.Now().Add(4 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	h := NewOAuthHandler(&OAuthConfig{TokenURL: server.URL}, store, "", "")
	h.RefreshAllTokens()
	got := store.Get("caesar")
	if got.AccessToken != "new" || got.RefreshToken != "refresh" || time.Until(got.ExpiresAt) < 59*time.Minute {
		t.Error("near-expiry grant not renewed correctly")
	}
}

func TestWebhookRefreshesExpiredTokenAndPersistsRotation(t *testing.T) {
	var refreshes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			refreshes.Add(1)
			_ = r.ParseForm()
			if r.Form.Get("refresh_token") != "refresh" {
				t.Error("used stale refresh token")
			}
			fmt.Fprint(w, `{"access_token":"new","refresh_token":"rotated","expires_in":3600}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer new" {
			t.Error("repository request used stale access token")
		}
		fmt.Fprint(w, `{"id":1,"name":"site","owner":{"username":"Caesar"}}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	key := bytes.Repeat([]byte("k"), 32)
	store, err := NewTokenStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Set("Caesar", &UserToken{AccessToken: "old", RefreshToken: "refresh", ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	h := NewOAuthHandler(&OAuthConfig{TokenURL: server.URL + "/token"}, store, "", "")
	v, err := NewRepositoryVerifier(server.URL, store)
	if err != nil {
		t.Fatal(err)
	}
	v.oauthHandler = h
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			repo, err := v.Verify(context.Background(), HookPrincipal{Username: "Caesar", ScopeType: ScopeUser, ScopeName: "Caesar"}, PayloadRepository{ID: 1, Name: "site", OwnerUsername: "Caesar"})
			if err != nil {
				t.Errorf("expired webhook token was not renewed: %v", err)
				return
			}
			if repo.AccessToken != "new" {
				t.Error("deployment received old token")
			}
			h.RefreshAllTokens()
		}()
	}
	wg.Wait()
	if refreshes.Load() != 1 {
		t.Errorf("refresh requests = %d, want 1", refreshes.Load())
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewTokenStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got := reopened.Get("caesar")
	if got.AccessToken != "new" || got.RefreshToken != "rotated" || time.Until(got.ExpiresAt) < 59*time.Minute {
		t.Error("refreshed grant was not persisted")
	}
}
