package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type recordingDeployments struct {
	mu          sync.Mutex
	deployments []VerifiedRepository
	targets     []SiteTarget
	removals    []SiteTarget
	deployErr   error
	removeErr   error
}

func (d *recordingDeployments) Deploy(_ context.Context, repo VerifiedRepository, target SiteTarget) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deployments = append(d.deployments, repo)
	d.targets = append(d.targets, target)
	return d.deployErr
}

func (d *recordingDeployments) Remove(_ context.Context, target SiteTarget) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.removals = append(d.removals, target)
	return d.removeErr
}

func (d *recordingDeployments) deploymentCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.deployments)
}

func (d *recordingDeployments) removalCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.removals)
}

type webhookHandlerFixture struct {
	deployer    *Deployer
	store       *TokenStore
	credential  HookCredential
	deployments *recordingDeployments
}

func newWebhookHandlerFixture(t *testing.T, principal HookPrincipal, repository RepoInfo) webhookHandlerFixture {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer "+principal.Username+"-token"; got != want {
			t.Errorf("repository lookup authorization = %q, want %q", got, want)
		}
		_ = json.NewEncoder(w).Encode(repository)
	}))
	t.Cleanup(server.Close)
	repository.CloneURL = server.URL + "/" + repository.Owner.Username + "/" + repository.Name + ".git"

	store := newMemoryHookStore(t)
	store.Set(principal.Username, &UserToken{AccessToken: principal.Username + "-token"})
	credential := HookCredential{
		Key:               "hook-" + principal.Username,
		Secret:            []byte("secret-" + principal.Username),
		PrincipalUsername: principal.Username,
		ScopeType:         principal.ScopeType,
		ScopeName:         principal.ScopeName,
		GiteaHookID:       1,
	}
	if err := store.PutHook(context.Background(), credential); err != nil {
		t.Fatalf("put hook: %v", err)
	}
	verifier, err := NewRepositoryVerifier(server.URL, store)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	deployments := &recordingDeployments{}
	return webhookHandlerFixture{
		deployer: NewWebhookDeployer(&Config{PagesDir: t.TempDir(), Domain: "example.com"}, store, verifier, deployments),
		store:    store, credential: credential, deployments: deployments,
	}
}

func webhookBody(t *testing.T, ref, after, owner, name string, id int64, extra string) []byte {
	t.Helper()
	body := `{"ref":` + quoteJSON(ref) + `,"after":` + quoteJSON(after) + `,"repository":{"id":` + jsonNumber(id) + `,"name":` + quoteJSON(name) + `,"owner":{"username":` + quoteJSON(owner) + `}` + extra + `}}`
	return []byte(body)
}

func quoteJSON(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func jsonNumber(value int64) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func computeSignature(body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

func canonicalRepository(id int64, owner, name, cloneURL string, private bool) RepoInfo {
	repository := RepoInfo{ID: id, Name: name, FullName: owner + "/" + name, CloneURL: cloneURL, Private: private, Size: 1}
	repository.Owner.Username = owner
	return repository
}

func dispatchWebhook(t *testing.T, deployer *Deployer, request *http.Request, event string) *httptest.ResponseRecorder {
	t.Helper()
	request.Header.Set("X-Gitea-Event", event)
	recorder := httptest.NewRecorder()
	deployer.HandleWebhook(recorder, request)
	return recorder
}

func TestHandleWebhookDeploysCanonicalRepositoryAndIgnoresPayloadCloneURL(t *testing.T) {
	principal := HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}
	fixture := newWebhookHandlerFixture(t, principal, canonicalRepository(7, "alice", "site", "", true))
	body := webhookBody(t, "refs/heads/gh-pages", "commit", "alice", "site", 7, `,"clone_url":"https://attacker.example/steal.git","private":false`)

	response := dispatchWebhook(t, fixture.deployer, signedHookRequest(body, fixture.credential.Key, fixture.credential.Secret, "delivery-1"), "push")

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
	if got := fixture.deployments.deploymentCount(); got != 1 {
		t.Fatalf("deployment count = %d, want 1", got)
	}
	if got := fixture.deployments.deployments[0].CloneURL.String(); got == "https://attacker.example/steal.git" {
		t.Fatalf("deployment accepted the payload clone URL %q", got)
	}
}

// This end-to-end handler regression uses the bcr root-site repository name
// with the complete configured Pages domain. It fails if root-site validation
// turns this valid authenticated webhook into a 400 response.
func TestHandleWebhookDeploysRootRepositoryForCompletePagesDomain(t *testing.T) {
	principal := HookPrincipal{Username: "bcr-admin", ScopeType: ScopeOrganization, ScopeName: "bcr"}
	fixture := newWebhookHandlerFixture(t, principal, canonicalRepository(104, "bcr", "bcr.pages.kekxv.com", "", false))
	fixture.deployer.config.Domain = "pages.kekxv.com"
	body := webhookBody(t, "refs/heads/gh-pages", "commit", "bcr", "bcr.pages.kekxv.com", 104, "")

	response := dispatchWebhook(t, fixture.deployer, signedHookRequest(body, fixture.credential.Key, fixture.credential.Secret, "delivery-bcr-root"), "push")
	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
	if got, want := fixture.deployments.deploymentCount(), 1; got != want {
		t.Fatalf("deployment count = %d, want %d", got, want)
	}
	if got, want := fixture.deployments.targets[0].Path(), filepath.Join(fixture.deployer.config.PagesDir, "bcr", "_root"); got != want {
		t.Fatalf("deployment target = %q, want %q", got, want)
	}
}

func TestHandleWebhookRemovesVerifiedGhPagesDelete(t *testing.T) {
	principal := HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}
	fixture := newWebhookHandlerFixture(t, principal, canonicalRepository(7, "alice", "site", "http://127.0.0.1/alice/site.git", false))
	body := []byte(`{"ref":"gh-pages","ref_type":"branch","repository":{"id":7,"name":"site","owner":{"username":"alice"}}}`)

	response := dispatchWebhook(t, fixture.deployer, signedHookRequest(body, fixture.credential.Key, fixture.credential.Secret, "delivery-delete"), "delete")

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
	if got := fixture.deployments.removalCount(); got != 1 {
		t.Fatalf("removal count = %d, want 1", got)
	}
}

func TestHandleWebhookRejectsCrossTenantPrivateRepositoryBeforeDeployment(t *testing.T) {
	principal := HookPrincipal{Username: "attacker", ScopeType: ScopeUser, ScopeName: "attacker"}
	fixture := newWebhookHandlerFixture(t, principal, canonicalRepository(9, "victim", "private", "http://127.0.0.1/victim/private.git", true))
	body := webhookBody(t, "refs/heads/gh-pages", "commit", "victim", "private", 9, `,"clone_url":"https://attacker.example/steal.git","private":false`)

	response := dispatchWebhook(t, fixture.deployer, signedHookRequest(body, fixture.credential.Key, fixture.credential.Secret, "delivery-idor"), "push")

	if got, want := response.Code, http.StatusForbidden; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
	if got := fixture.deployments.deploymentCount(); got != 0 {
		t.Fatalf("Git deployment invoked %d times for cross-tenant event", got)
	}
}

func TestHandleWebhookLogsSafeRepositoryFailureCategory(t *testing.T) {
	principal := HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}
	fixture := newWebhookHandlerFixture(t, principal, canonicalRepository(9, "victim", "private", "http://127.0.0.1/victim/private.git", true))
	body := webhookBody(t, "refs/heads/gh-pages", "commit", "victim", "private", 9, "")

	var logs bytes.Buffer
	previousOutput, previousFlags, previousPrefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&logs)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	response := dispatchWebhook(t, fixture.deployer, signedHookRequest(body, fixture.credential.Key, fixture.credential.Secret, "delivery-out-of-scope"), "push")
	if got, want := response.Code, http.StatusForbidden; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if got, want := logs.String(), "Webhook repository verification failed: repository out of scope\n"; got != want {
		t.Errorf("log output = %q, want %q", got, want)
	}
	if strings.Contains(logs.String(), "victim") || strings.Contains(logs.String(), "private") {
		t.Fatal("repository verification log leaked repository metadata")
	}
}

// This test fails if an unexpected clone origin is logged without a safe,
// actionable category, or if the error text leaks the URL supplied by Gitea.
func TestLogWebhookRepositoryFailureClassifiesCloneOriginMismatch(t *testing.T) {
	var logs bytes.Buffer
	previousOutput, previousFlags, previousPrefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&logs)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	logWebhookRepositoryFailure(ErrCloneURLOriginMismatch)
	if got, want := logs.String(), "Webhook repository verification failed: untrusted clone URL: origin mismatch\n"; got != want {
		t.Errorf("log output = %q, want %q", got, want)
	}
	if strings.Contains(logs.String(), "gitea.example.com") || strings.Contains(logs.String(), "alice/site") {
		t.Fatal("repository verification log leaked clone URL metadata")
	}
}

func TestHandleWebhookRejectsReplayBeforeDeployment(t *testing.T) {
	principal := HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}
	fixture := newWebhookHandlerFixture(t, principal, canonicalRepository(7, "alice", "site", "http://127.0.0.1/alice/site.git", false))
	body := webhookBody(t, "refs/heads/gh-pages", "commit", "alice", "site", 7, "")

	first := dispatchWebhook(t, fixture.deployer, signedHookRequest(body, fixture.credential.Key, fixture.credential.Secret, "delivery-replay"), "push")
	second := dispatchWebhook(t, fixture.deployer, signedHookRequest(body, fixture.credential.Key, fixture.credential.Secret, "delivery-replay"), "push")

	if got, want := first.Code, http.StatusOK; got != want {
		t.Fatalf("first status = %d, want %d", got, want)
	}
	if got, want := second.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("replay status = %d, want %d", got, want)
	}
	if got := fixture.deployments.deploymentCount(); got != 1 {
		t.Fatalf("deployment count = %d, want 1", got)
	}
}

func TestHandleWebhookRejectsUnknownAndBearerKeysBeforeDeployment(t *testing.T) {
	principal := HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}
	fixture := newWebhookHandlerFixture(t, principal, canonicalRepository(7, "alice", "site", "http://127.0.0.1/alice/site.git", false))
	body := webhookBody(t, "refs/heads/gh-pages", "commit", "alice", "site", 7, "")

	unknown := signedHookRequest(body, "unknown-key", []byte("unknown-secret"), "delivery-unknown")
	bearer := signedHookRequest(body, fixture.credential.Key, fixture.credential.Secret, "delivery-bearer")
	bearer.Header.Set("Authorization", "Bearer eyJ1c2VybmFtZSI6ImFsaWNlIn0")
	for name, request := range map[string]*http.Request{"unknown": unknown, "bearer": bearer} {
		t.Run(name, func(t *testing.T) {
			response := dispatchWebhook(t, fixture.deployer, request, "push")
			if got, want := response.Code, http.StatusUnauthorized; got != want {
				t.Fatalf("status = %d, want %d", got, want)
			}
		})
	}
	if got := fixture.deployments.deploymentCount(); got != 0 {
		t.Fatalf("Git deployment invoked %d times for rejected authorization", got)
	}
}

func TestHandleWebhookLogsSafeAuthenticationFailureCategory(t *testing.T) {
	principal := HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}
	fixture := newWebhookHandlerFixture(t, principal, canonicalRepository(7, "alice", "site", "http://127.0.0.1/alice/site.git", false))
	body := webhookBody(t, "refs/heads/gh-pages", "commit", "alice", "site", 7, "")
	request := signedHookRequest(body, fixture.credential.Key, fixture.credential.Secret, "delivery-bad-authorization")
	request.Header.Set("Authorization", "Bearer do-not-log-this-value")

	var logs bytes.Buffer
	previousOutput, previousFlags, previousPrefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&logs)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	response := dispatchWebhook(t, fixture.deployer, request, "push")
	if got, want := response.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if got, want := logs.String(), "Webhook authentication failed: invalid authorization\n"; got != want {
		t.Errorf("log output = %q, want %q", got, want)
	}
	if strings.Contains(logs.String(), "do-not-log-this-value") {
		t.Fatal("authentication failure log leaked the Authorization header")
	}
}

func TestHandleWebhookReturnsRetryAfterWhenDeploymentCapacityIsSaturated(t *testing.T) {
	principal := HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}
	fixture := newWebhookHandlerFixture(t, principal, canonicalRepository(7, "alice", "site", "http://127.0.0.1/alice/site.git", false))
	fixture.deployments.deployErr = ErrDeploymentSaturated
	body := webhookBody(t, "refs/heads/gh-pages", "commit", "alice", "site", 7, "")

	response := dispatchWebhook(t, fixture.deployer, signedHookRequest(body, fixture.credential.Key, fixture.credential.Secret, "delivery-saturated"), "push")

	if got, want := response.Code, http.StatusTooManyRequests; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
	if got, want := response.Header().Get("Retry-After"), "30"; got != want {
		t.Fatalf("Retry-After = %q, want %q", got, want)
	}
}

func TestHandleWebhookMapsMalformedAndOversizedRepositoryFailures(t *testing.T) {
	principal := HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}
	fixture := newWebhookHandlerFixture(t, principal, canonicalRepository(7, "alice", "site", "http://127.0.0.1/alice/site.git", false))
	malformed := []byte(`{"repository":`)
	malformedResponse := dispatchWebhook(t, fixture.deployer, signedHookRequest(malformed, fixture.credential.Key, fixture.credential.Secret, "delivery-malformed"), "push")
	if got, want := malformedResponse.Code, http.StatusBadRequest; got != want {
		t.Fatalf("malformed status = %d, want %d", got, want)
	}
	fixture.deployments.deployErr = errors.Join(ErrRepositoryTooLarge, errors.New("limit"))
	body := webhookBody(t, "refs/heads/gh-pages", "commit", "alice", "site", 7, "")
	tooLargeResponse := dispatchWebhook(t, fixture.deployer, signedHookRequest(body, fixture.credential.Key, fixture.credential.Secret, "delivery-large"), "push")
	if got, want := tooLargeResponse.Code, http.StatusRequestEntityTooLarge; got != want {
		t.Fatalf("oversized status = %d, want %d", got, want)
	}
}

func TestHandleWebhookMethodCheck(t *testing.T) {
	deployer := NewWebhookDeployer(&Config{PagesDir: t.TempDir(), Domain: "example.com"}, nil, nil, nil)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			response := httptest.NewRecorder()
			deployer.HandleWebhook(response, httptest.NewRequest(method, "/webhook", nil))
			if got, want := response.Code, http.StatusMethodNotAllowed; got != want {
				t.Fatalf("status = %d, want %d", got, want)
			}
		})
	}
}

var _ DeploymentExecutor = (*recordingDeployments)(nil)
