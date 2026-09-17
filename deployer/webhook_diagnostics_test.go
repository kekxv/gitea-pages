package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookErrorDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{{ErrRepositoryAccess, 503, "oauth_token_unavailable"}, {&GiteaAPIError{StatusCode: 401}, 502, "gitea_token_rejected"}, {&GiteaAPIError{StatusCode: 403}, 403, "gitea_repository_forbidden"}, {&GiteaAPIError{StatusCode: 404}, 404, "gitea_repository_not_found"}, {ErrRepositoryMismatch, 403, "repository_mismatch"}, {ErrInvalidSignature, 401, "invalid_signature"}, {errors.New("sensitive-token"), 500, "internal_error"}} {
		w := httptest.NewRecorder()
		writeWebhookError(w, tc.err)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) {
			t.Errorf("%v: %d %s", tc.err, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "sensitive-token") {
			t.Fatal("error leaked")
		}
	}
}
func TestRegistrationReusesValidHook(t *testing.T) {
	store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p := HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}
	c, err := createHookCredential(p)
	if err != nil {
		t.Fatal(err)
	}
	c.GiteaHookID = 42
	if err = store.PutHook(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RecordDelivery(context.Background(), c.Key, "historic", time.Now()); err != nil {
		t.Fatal(err)
	}
	mut := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mut++
			http.Error(w, "unexpected", 500)
			return
		}
		json.NewEncoder(w).Encode([]webhookInfo{{ID: 42, Type: "gitea", Active: true, BranchFilter: "gh-pages", Events: []string{"delete", "push"}, Config: webhookConfig{URL: "https://pages.example.com/webhook", ContentType: "json"}, AuthorizationHeader: "Gitea-Pages " + base64.RawURLEncoding.EncodeToString([]byte(c.Key))}})
	}))
	defer s.Close()
	h := NewOAuthHandler(&OAuthConfig{APIURL: s.URL}, store, "https://pages.example.com/webhook", "session")
	if err := h.registerUserWebhook("access", "alice"); err != nil {
		t.Fatal(err)
	}
	if mut != 0 {
		t.Fatalf("mutations=%d", mut)
	}
	ins, err := store.RecordDelivery(context.Background(), c.Key, "historic", time.Now())
	if err != nil || ins {
		t.Fatalf("history lost: %v %v", ins, err)
	}
}
func TestRegistrationListFailureDoesNotCreateHook(t *testing.T) {
	mut := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mut++
		}
		http.Error(w, "unavailable", 503)
	}))
	defer s.Close()
	store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h := NewOAuthHandler(&OAuthConfig{APIURL: s.URL}, store, "https://pages.example.com/webhook", "session")
	if err := h.registerUserWebhook("access", "alice"); err == nil {
		t.Fatal("list failure ignored")
	}
	if mut != 0 {
		t.Fatalf("mutations=%d", mut)
	}
}
