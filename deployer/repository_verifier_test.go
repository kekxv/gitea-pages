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
	"time"
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

// This test fails if a clone URL returned by the repository API can override
// the configured Gitea origin after the repository identity is verified.
func TestVerifyRepositoryDerivesCloneURLFromConfiguredGiteaOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		repo := RepoInfo{ID: 7, Name: "site", FullName: "platform/site", CloneURL: "ssh://git@git.kekxv.com/platform/site.git"}
		repo.Owner.Username = "platform"
		_ = json.NewEncoder(w).Encode(repo)
	}))
	defer server.Close()

	store := newTestTokenStore(t)
	t.Cleanup(func() { _ = store.Close() })
	store.Set("maintainer", &UserToken{AccessToken: "principal-token"})
	verifier, err := NewRepositoryVerifierWithPublicURL(server.URL, "https://gitea.example.com/gitea", store)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	verified, err := verifier.Verify(context.Background(), HookPrincipal{Username: "maintainer", ScopeType: ScopeOrganization, ScopeName: "platform"}, PayloadRepository{ID: 7, Name: "site", OwnerUsername: "platform"})
	if err != nil {
		t.Fatalf("verify repository: %v", err)
	}
	if got, want := verified.CloneURL.String(), "https://gitea.example.com/gitea/platform/site.git"; got != want {
		t.Fatalf("clone URL = %q, want configured Gitea origin %q", got, want)
	}
}

// This test fails if an authenticated organization hook cannot continue with
// another administrator that previously authorized that same hook scope.
func TestVerifyOrganizationHookUsesValidAuthorizedAdministratorWhenPrincipalTokenUnavailable(t *testing.T) {
	var receivedAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthorization = r.Header.Get("Authorization")
		repo := RepoInfo{ID: 7, Name: "site", FullName: "platform/site", CloneURL: serverCloneURL(r)}
		repo.Owner.Username = "platform"
		_ = json.NewEncoder(w).Encode(repo)
	}))
	defer server.Close()

	for _, test := range []struct {
		name           string
		principalToken *UserToken
	}{
		{name: "expired token", principalToken: &UserToken{AccessToken: "expired-principal-token", ExpiresAt: time.Now().Add(-time.Minute)}},
		{name: "missing token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			receivedAuthorization = ""
			store := newTestTokenStore(t)
			t.Cleanup(func() { _ = store.Close() })
			if test.principalToken != nil {
				store.Set("alice", test.principalToken)
			}
			store.Set("bob", &UserToken{AccessToken: "administrator-token"})
			if err := store.PutOrganizationHookAuthorizer(context.Background(), "platform", "alice", "platform-hook"); err != nil {
				t.Fatalf("save original administrator: %v", err)
			}
			if err := store.PutOrganizationHookAuthorizer(context.Background(), "platform", "bob", "platform-hook"); err != nil {
				t.Fatalf("save replacement administrator: %v", err)
			}
			verifier, err := NewRepositoryVerifier(server.URL, store)
			if err != nil {
				t.Fatalf("new verifier: %v", err)
			}

			verified, err := verifier.Verify(context.Background(), HookPrincipal{Username: "alice", ScopeType: ScopeOrganization, ScopeName: "platform"}, PayloadRepository{ID: 7, Name: "site", OwnerUsername: "platform"})
			if err != nil {
				t.Fatalf("verify repository: %v", err)
			}
			if got, want := receivedAuthorization, "Bearer administrator-token"; got != want {
				t.Errorf("repository lookup authorization = %q, want %q", got, want)
			}
			if got, want := verified.AccessToken, "administrator-token"; got != want {
				t.Errorf("verified repository access token = %q, want %q", got, want)
			}
		})
	}
}

// This test fails if an upgraded organization hook with no retained principal
// username is rejected before its persistent administrator pool is consulted.
func TestVerifyOrganizationHookUsesAuthorizedAdministratorWhenLegacyPrincipalIsEmpty(t *testing.T) {
	var receivedAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthorization = r.Header.Get("Authorization")
		repo := RepoInfo{ID: 7, Name: "site", FullName: "platform/site", CloneURL: serverCloneURL(r)}
		repo.Owner.Username = "platform"
		_ = json.NewEncoder(w).Encode(repo)
	}))
	defer server.Close()

	store := newTestTokenStore(t)
	t.Cleanup(func() { _ = store.Close() })
	store.Set("alice", &UserToken{AccessToken: "administrator-token"})
	if err := store.PutOrganizationHookAuthorizer(context.Background(), "platform", "alice", "platform-hook"); err != nil {
		t.Fatalf("save organization administrator: %v", err)
	}
	verifier, err := NewRepositoryVerifier(server.URL, store)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	verified, err := verifier.Verify(context.Background(), HookPrincipal{ScopeType: ScopeOrganization, ScopeName: "platform"}, PayloadRepository{ID: 7, Name: "site", OwnerUsername: "platform"})
	if err != nil {
		t.Fatalf("verify repository: %v", err)
	}
	if got, want := receivedAuthorization, "Bearer administrator-token"; got != want {
		t.Errorf("repository lookup authorization = %q, want %q", got, want)
	}
	if got, want := verified.AccessToken, "administrator-token"; got != want {
		t.Errorf("verified repository access token = %q, want %q", got, want)
	}
}

// This test fails if a legacy organization-authorizer row cannot be found
// after Gitea changes only the casing of its organization username.
func TestOrganizationHookAuthorizersMatchesOrganizationNameCaseInsensitively(t *testing.T) {
	store := newTestTokenStore(t)
	t.Cleanup(func() { _ = store.Close() })
	if err := store.PutOrganizationHookAuthorizer(context.Background(), "Platform", "alice", "platform-hook"); err != nil {
		t.Fatalf("save organization administrator: %v", err)
	}

	authorizers, err := store.OrganizationHookAuthorizers(context.Background(), "platform")
	if err != nil {
		t.Fatalf("load organization administrators: %v", err)
	}
	if got, want := strings.Join(authorizers, ","), "alice"; got != want {
		t.Fatalf("organization administrators = %q, want %q", got, want)
	}
}

// This test fails if a user-scoped hook can borrow an organization
// administrator token when its own token is unavailable.
func TestVerifyUserHookDoesNotFallBackToOrganizationAdministratorToken(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "unexpected repository lookup", http.StatusInternalServerError)
	}))
	defer server.Close()

	store := newTestTokenStore(t)
	t.Cleanup(func() { _ = store.Close() })
	store.Set("bob", &UserToken{AccessToken: "administrator-token"})
	if err := store.PutOrganizationHookAuthorizer(context.Background(), "alice", "bob", "alice-hook"); err != nil {
		t.Fatalf("save organization administrator: %v", err)
	}
	verifier, err := NewRepositoryVerifier(server.URL, store)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	_, err = verifier.Verify(context.Background(), HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}, PayloadRepository{ID: 7, Name: "site", OwnerUsername: "alice"})
	if !errors.Is(err, ErrRepositoryAccess) {
		t.Fatalf("verify repository error = %v, want %v", err, ErrRepositoryAccess)
	}
	if requests != 0 {
		t.Errorf("repository lookup requests = %d, want 0", requests)
	}
}

// This test fails if an organization hook can borrow an administrator token
// that authorized a different organization.
func TestVerifyOrganizationHookDoesNotUseOtherOrganizationAdministratorToken(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "unexpected repository lookup", http.StatusInternalServerError)
	}))
	defer server.Close()

	store := newTestTokenStore(t)
	t.Cleanup(func() { _ = store.Close() })
	store.Set("mallory", &UserToken{AccessToken: "other-organization-token"})
	if err := store.PutOrganizationHookAuthorizer(context.Background(), "other-organization", "mallory", "other-hook"); err != nil {
		t.Fatalf("save other organization administrator: %v", err)
	}
	verifier, err := NewRepositoryVerifier(server.URL, store)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	_, err = verifier.Verify(context.Background(), HookPrincipal{Username: "alice", ScopeType: ScopeOrganization, ScopeName: "platform"}, PayloadRepository{ID: 7, Name: "site", OwnerUsername: "platform"})
	if !errors.Is(err, ErrRepositoryAccess) {
		t.Fatalf("verify repository error = %v, want %v", err, ErrRepositoryAccess)
	}
	if requests != 0 {
		t.Errorf("repository lookup requests = %d, want 0", requests)
	}
}

// This test fails if a cross-owner organization payload can trigger either an
// administrator-pool lookup token or a canonical Gitea request before scope
// validation rejects it.
func TestVerifyOrganizationHookRejectsCrossOwnerBeforeAdministratorTokenFallback(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		repo := RepoInfo{ID: 7, Name: "site", FullName: "victim/site", CloneURL: serverCloneURL(r)}
		repo.Owner.Username = "victim"
		_ = json.NewEncoder(w).Encode(repo)
	}))
	defer server.Close()

	store := newTestTokenStore(t)
	t.Cleanup(func() { _ = store.Close() })
	store.Set("bob", &UserToken{AccessToken: "administrator-token"})
	if err := store.PutOrganizationHookAuthorizer(context.Background(), "platform", "bob", "platform-hook"); err != nil {
		t.Fatalf("save organization administrator: %v", err)
	}
	verifier, err := NewRepositoryVerifier(server.URL, store)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	_, err = verifier.Verify(context.Background(), HookPrincipal{Username: "alice", ScopeType: ScopeOrganization, ScopeName: "platform"}, PayloadRepository{ID: 7, Name: "site", OwnerUsername: "victim"})
	if !errors.Is(err, ErrRepositoryOutOfScope) {
		t.Fatalf("verify repository error = %v, want %v", err, ErrRepositoryOutOfScope)
	}
	if requests != 0 {
		t.Errorf("canonical Gitea requests = %d, want 0", requests)
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

// This test fails if an operator cannot distinguish an unexpected Gitea
// origin from other rejected clone URL forms without logging the URL itself.
func TestValidateCanonicalCloneURLClassifiesOriginMismatch(t *testing.T) {
	apiBase, err := url.Parse("https://gitea.example.com")
	if err != nil {
		t.Fatal(err)
	}

	_, err = ValidateCanonicalCloneURL("https://gitea.example.com:8443/alice/site.git", apiBase)
	if !errors.Is(err, ErrUntrustedCloneURL) {
		t.Fatalf("ValidateCanonicalCloneURL() error = %v, want untrusted clone URL", err)
	}
	if !strings.Contains(err.Error(), "origin mismatch") {
		t.Fatalf("clone URL rejection = %q, want origin mismatch category", err)
	}
}

// This regression test uses the deployed Gitea API origin and canonical clone
// URL reported for Caesar/blog. It fails if a normal HTTPS Gitea clone URL at
// that same origin is rejected.
func TestValidateCanonicalCloneURLAcceptsConfiguredGiteaOrigin(t *testing.T) {
	apiBase, err := url.Parse("https://git.kekxv.com")
	if err != nil {
		t.Fatal(err)
	}

	cloneURL, err := ValidateCanonicalCloneURL("https://git.kekxv.com/Caesar/blog.git", apiBase)
	if err != nil {
		t.Fatalf("ValidateCanonicalCloneURL() error = %v, want accepted configured Gitea origin", err)
	}
	if got, want := cloneURL.String(), "https://git.kekxv.com/Caesar/blog.git"; got != want {
		t.Fatalf("clone URL = %q, want %q", got, want)
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
