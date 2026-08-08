package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestVerifyRepositoryRejectsUserHookForDifferentOwner(t *testing.T) {
	verifier := newVerifierWithRepo(t, RepoInfo{ID: 9, Name: "private", FullName: "victim/private", Private: true, CloneURL: "https://gitea.example.com/victim/private.git"})
	principal := HookPrincipal{Username: "attacker", ScopeType: ScopeUser, ScopeName: "attacker"}
	_, err := verifier.Verify(context.Background(), principal, PayloadRepository{ID: 9, Name: "private", OwnerUsername: "victim"})
	if !errors.Is(err, ErrRepositoryOutOfScope) {
		t.Fatalf("expected scope rejection, got %v", err)
	}
}

func TestVerifyRepositoryRejectsOrganizationHookForDifferentOwner(t *testing.T) {
	verifier := newVerifierWithRepo(t, RepoInfo{ID: 9, Name: "private", FullName: "victim/private", Private: true, CloneURL: "https://gitea.example.com/victim/private.git"})
	principal := HookPrincipal{Username: "maintainer", ScopeType: ScopeOrganization, ScopeName: "platform"}
	_, err := verifier.Verify(context.Background(), principal, PayloadRepository{ID: 9, Name: "private", OwnerUsername: "victim"})
	if !errors.Is(err, ErrRepositoryOutOfScope) {
		t.Fatalf("expected scope rejection, got %v", err)
	}
}

func TestVerifyRepositoryRejectsPayloadIDMismatch(t *testing.T) {
	verifier := newVerifierWithRepo(t, RepoInfo{ID: 10, Name: "site", FullName: "alice/site", CloneURL: "https://gitea.example.com/alice/site.git"})
	_, err := verifier.Verify(context.Background(), HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}, PayloadRepository{ID: 11, Name: "site", OwnerUsername: "alice"})
	if !errors.Is(err, ErrRepositoryMismatch) {
		t.Fatalf("expected ID mismatch, got %v", err)
	}
}

func TestVerifyRepositoryUsesPrincipalTokenAndCanonicalMetadata(t *testing.T) {
	var receivedAuthorization, receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthorization = r.Header.Get("Authorization")
		receivedPath = r.URL.Path
		repo := RepoInfo{
			ID:       7,
			Name:     "site",
			FullName: "platform/site",
			Private:  true,
			Size:     12,
			CloneURL: serverCloneURL(r),
		}
		repo.Owner.Username = "platform"
		_ = json.NewEncoder(w).Encode(repo)
	}))
	defer server.Close()

	store := newTestTokenStore(t)
	t.Cleanup(func() { _ = store.Close() })
	store.Set("maintainer", &UserToken{AccessToken: "principal-token"})
	verifier, err := NewRepositoryVerifier(server.URL, store)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	verified, err := verifier.Verify(context.Background(), HookPrincipal{Username: "maintainer", ScopeType: ScopeOrganization, ScopeName: "platform"}, PayloadRepository{ID: 7, Name: "site", OwnerUsername: "platform"})
	if err != nil {
		t.Fatalf("verify repository: %v", err)
	}
	if receivedAuthorization != "Bearer principal-token" {
		t.Fatalf("lookup used %q authorization, want principal token", receivedAuthorization)
	}
	if got, want := receivedPath, "/api/v1/repos/platform/site"; got != want {
		t.Fatalf("repository lookup path = %q, want %q", got, want)
	}
	if got, want := verified.AccessToken, "principal-token"; got != want {
		t.Fatalf("access token = %q, want %q", got, want)
	}
	if got, want := verified.CloneURL.String(), serverCloneURLFromBase(t, server.URL); got != want {
		t.Fatalf("clone URL = %q, want canonical %q", got, want)
	}
	if got, want := verified.SizeBytes, int64(12*1024); got != want {
		t.Fatalf("size bytes = %d, want %d", got, want)
	}
}

func TestValidateCanonicalCloneURL(t *testing.T) {
	httpsBase, err := url.Parse("https://gitea.example.com/api/v1")
	if err != nil {
		t.Fatal(err)
	}
	localHTTPBase, err := url.Parse("http://localhost:3000/api/v1")
	if err != nil {
		t.Fatal(err)
	}
	remoteHTTPBase, err := url.Parse("http://gitea.example.com/api/v1")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		raw     string
		apiBase *url.URL
		wantErr error
	}{
		{name: "canonical HTTPS", raw: "https://gitea.example.com/alice/site.git", apiBase: httpsBase},
		{name: "rejects credentials", raw: "https://token@gitea.example.com/alice/site.git", apiBase: httpsBase, wantErr: ErrUntrustedCloneURL},
		{name: "rejects different port", raw: "https://gitea.example.com:8443/alice/site.git", apiBase: httpsBase, wantErr: ErrUntrustedCloneURL},
		{name: "rejects query", raw: "https://gitea.example.com/alice/site.git?token=attacker", apiBase: httpsBase, wantErr: ErrUntrustedCloneURL},
		{name: "rejects non git path", raw: "https://gitea.example.com/alice/site", apiBase: httpsBase, wantErr: ErrUntrustedCloneURL},
		{name: "allows local development HTTP", raw: "http://localhost:3000/alice/site.git", apiBase: localHTTPBase},
		{name: "rejects remote HTTP", raw: "http://gitea.example.com/alice/site.git", apiBase: remoteHTTPBase, wantErr: ErrUntrustedCloneURL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateCanonicalCloneURL(tt.raw, tt.apiBase)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateCanonicalCloneURL() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && got.String() != tt.raw {
				t.Fatalf("clone URL = %q, want %q", got, tt.raw)
			}
		})
	}
}

func TestDecodeWebhookExtractsOnlyCanonicalLookupFields(t *testing.T) {
	body := []byte(`{
		"ref":"refs/heads/gh-pages",
		"after":"abc123",
		"repository":{
			"id":7,
			"name":"site",
			"owner":{"username":"platform"},
			"clone_url":"https://attacker.example/steal.git",
			"private":false
		}
	}`)

	event, err := DecodeWebhook(body, "push")
	if err != nil {
		t.Fatalf("decode webhook: %v", err)
	}
	if got, want := event.Kind, "push"; got != want {
		t.Fatalf("event kind = %q, want %q", got, want)
	}
	if got, want := event.Repository, (PayloadRepository{ID: 7, Name: "site", OwnerUsername: "platform"}); got != want {
		t.Fatalf("payload repository = %#v, want %#v", got, want)
	}
}

func newVerifierWithRepo(t *testing.T, repo RepoInfo) RepositoryVerifier {
	t.Helper()
	if repo.Owner.Username == "" {
		repo.Owner.Username = strings.SplitN(repo.FullName, "/", 2)[0]
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(repo)
	}))
	t.Cleanup(server.Close)

	store := newTestTokenStore(t)
	t.Cleanup(func() { _ = store.Close() })
	for _, username := range []string{"alice", "attacker", "maintainer"} {
		store.Set(username, &UserToken{AccessToken: username + "-token"})
	}
	verifier, err := NewRepositoryVerifier(server.URL, store)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return verifier
}

func serverCloneURL(r *http.Request) string {
	return "http://" + r.Host + "/platform/site.git"
}

func serverCloneURLFromBase(t *testing.T, rawBase string) string {
	t.Helper()
	base, err := url.Parse(rawBase)
	if err != nil {
		t.Fatal(err)
	}
	return "http://" + base.Host + "/platform/site.git"
}
