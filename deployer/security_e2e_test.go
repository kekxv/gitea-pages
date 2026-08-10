package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// securityE2EFixture starts the actual webhook HTTP handler with its SQLite
// hook store, canonical Gitea API verifier, deployment limiter, and Git
// publisher. The only doubles are the remote Gitea API and Git executable.
type securityE2EFixture struct {
	t              *testing.T
	pages          string
	store          *TokenStore
	gitea          *securityE2EGitea
	giteaServer    *httptest.Server
	webhookServer  *httptest.Server
	service        *DeploymentService
	gitMarker      string
	cloneOriginURL string
}

type securityE2EGitea struct {
	mu          sync.Mutex
	repos       map[string]RepoInfo
	defaultRepo *RepoInfo
	redirectURL string
	lookups     int
}

func (g *securityE2EGitea) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lookups++
	if g.redirectURL != "" {
		http.Redirect(w, r, g.redirectURL, http.StatusFound)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v1/repos/") {
		http.NotFound(w, r)
		return
	}
	if g.defaultRepo != nil {
		_ = json.NewEncoder(w).Encode(g.defaultRepo)
		return
	}
	repo, ok := g.repos[strings.TrimPrefix(r.URL.Path, "/api/v1/repos/")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	_ = json.NewEncoder(w).Encode(repo)
}

func newSecurityE2EFixture(t *testing.T) *securityE2EFixture {
	t.Helper()
	pages := filepath.Join(t.TempDir(), "pages")
	if err := os.Mkdir(pages, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gitea := &securityE2EGitea{repos: make(map[string]RepoInfo)}
	giteaServer := httptest.NewServer(gitea)
	t.Cleanup(giteaServer.Close)

	for _, user := range []string{"alice", "bob"} {
		store.Set(user, &UserToken{Username: user, AccessToken: user + "-token"})
		credential := HookCredential{
			Key:               user + "-hook",
			Secret:            []byte(user + "-secret"),
			PrincipalUsername: user,
			ScopeType:         ScopeUser,
			ScopeName:         user,
			GiteaHookID:       int64(len(user)),
		}
		if err := store.PutHook(context.Background(), credential); err != nil {
			t.Fatal(err)
		}
	}
	cloneOriginURL := "https://" + strings.TrimPrefix(giteaServer.URL, "http://")
	verifier, err := NewRepositoryVerifierWithPublicURL(giteaServer.URL, cloneOriginURL, store)
	if err != nil {
		t.Fatal(err)
	}
	config := &Config{
		Domain:               "pages.test",
		PagesDir:             pages,
		MaxConcurrentDeploys: 1,
		AcquireTimeout:       time.Second,
		CloneTimeout:         100 * time.Millisecond,
		MaxRepositorySizeMB:  10,
		MaxSiteSizeMB:        10,
	}
	service := NewDeploymentService(config)
	marker := filepath.Join(t.TempDir(), "git-invocations")
	service.gitOps.gitBinary = securityE2ENormalGit(t, marker)
	deployer := NewWebhookDeployer(config, store, verifier, service)
	webhookServer := httptest.NewServer(http.HandlerFunc(deployer.HandleWebhook))
	t.Cleanup(webhookServer.Close)
	return &securityE2EFixture{
		t: t, pages: pages, store: store, gitea: gitea, giteaServer: giteaServer,
		webhookServer: webhookServer, service: service, gitMarker: marker,
		cloneOriginURL: cloneOriginURL,
	}
}

func (f *securityE2EFixture) addRepo(id int64, owner, name string, private bool) {
	f.t.Helper()
	repo := securityE2ECanonicalRepository(id, owner, name, f.cloneOriginURL+"/"+owner+"/"+name+".git", private)
	f.gitea.mu.Lock()
	f.gitea.repos[owner+"/"+name] = repo
	f.gitea.mu.Unlock()
}

func (f *securityE2EFixture) setCanonicalRepo(repo RepoInfo) {
	f.t.Helper()
	f.gitea.mu.Lock()
	f.gitea.defaultRepo = &repo
	f.gitea.mu.Unlock()
}

func (f *securityE2EFixture) deliver(event, key, secret, deliveryID string, body []byte) *http.Response {
	f.t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.webhookServer.URL, bytes.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Gitea-Pages "+base64.RawURLEncoding.EncodeToString([]byte(key)))
	req.Header.Set("X-Gitea-Delivery", deliveryID)
	req.Header.Set("X-Gitea-Event", event)
	req.Header.Set("X-Gitea-Signature", securityE2ESignature(body, []byte(secret)))
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return response
}

func securityE2EWebhookBody(event, owner, name string, id int64, extra string) []byte {
	refType := ""
	if event == "delete" {
		refType = `,"ref_type":"branch"`
	}
	return []byte(fmt.Sprintf(`{"ref":"%s","after":"commit","repository":{"id":%d,"name":%s,"owner":{"username":%s}%s}%s}`,
		map[string]string{"push": "refs/heads/gh-pages", "delete": "gh-pages"}[event], id, securityE2EQuoteJSON(name), securityE2EQuoteJSON(owner), extra, refType))
}

func securityE2ESignature(body, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func securityE2EQuoteJSON(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func securityE2ECanonicalRepository(id int64, owner, name, cloneURL string, private bool) RepoInfo {
	repository := RepoInfo{ID: id, Name: name, FullName: owner + "/" + name, CloneURL: cloneURL, Private: private, Size: 1}
	repository.Owner.Username = owner
	return repository
}

func responseStatus(t *testing.T, response *http.Response) int {
	t.Helper()
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode
}

func securityE2ENormalGit(t *testing.T, marker string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "git")
	contents := "#!/bin/sh\nprintf 'clone\\n' >> " + shellQuote(marker) + "\nfor arg do target=$arg; done\nmkdir -p \"$target\"\nprintf '<h1>new site</h1>' > \"$target/index.html\"\n"
	if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func securityE2EFirstCloneHangsThenSucceeds(t *testing.T, marker, started string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "git")
	contents := "#!/bin/sh\nif [ ! -e " + shellQuote(started) + " ]; then\n  : > " + shellQuote(started) + "\n  printf 'hang\\n' >> " + shellQuote(marker) + "\n  while :; do :; done\nfi\nprintf 'clone\\n' >> " + shellQuote(marker) + "\nfor arg do target=$arg; done\nmkdir -p \"$target\"\nprintf '<h1>new site</h1>' > \"$target/index.html\"\n"
	if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func securityE2EGitInvocations(t *testing.T, marker string) []string {
	t.Helper()
	contents, err := os.ReadFile(marker)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(contents))
}

func securityE2EWriteSentinels(t *testing.T, pages string) map[string][]byte {
	t.Helper()
	sentinels := map[string][]byte{
		filepath.Join(pages, "root-sentinel"):         []byte("root must survive"),
		filepath.Join(pages, "alice", "sentinel"):     []byte("alice must survive"),
		filepath.Join(pages, "bob", "sentinel"):       []byte("bob must survive"),
		filepath.Join(pages, "bob", "alice-sentinel"): []byte("alice must not appear in bob"),
	}
	for path, contents := range sentinels {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return sentinels
}

func securityE2EAssertSentinels(t *testing.T, sentinels map[string][]byte) {
	t.Helper()
	for path, want := range sentinels {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("sentinel %q changed: %q, %v; want %q", path, got, err, want)
		}
	}
}

type securityE2ETreeEntry struct {
	mode     os.FileMode
	contents []byte
	target   string
}

func securityE2ESnapshotPagesTree(t *testing.T, root string) map[string]securityE2ETreeEntry {
	t.Helper()
	snapshot := make(map[string]securityE2ETreeEntry)
	if err := filepath.WalkDir(root, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entry := securityE2ETreeEntry{mode: info.Mode()}
		switch {
		case info.Mode().IsRegular():
			entry.contents, err = os.ReadFile(path)
		case info.Mode()&os.ModeSymlink != 0:
			entry.target, err = os.Readlink(path)
		}
		if err != nil {
			return err
		}
		snapshot[filepath.ToSlash(relative)] = entry
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func securityE2EAssertPagesTreeUnchanged(t *testing.T, before map[string]securityE2ETreeEntry, root string) {
	t.Helper()
	if after := securityE2ESnapshotPagesTree(t, root); !reflect.DeepEqual(after, before) {
		t.Fatalf("Pages tree changed after rejected delivery: before = %#v, after = %#v", before, after)
	}
}

// This would fail if a hook key could be paired with another tenant's secret,
// or if signed payload fields could select a private repository outside the
// authenticated hook principal's scope.
func TestSecurityE2ECrossTenantPrivateRepositoryNeverReachesGit(t *testing.T) {
	f := newSecurityE2EFixture(t)
	f.addRepo(11, "alice", "private", true)
	f.addRepo(22, "bob", "site", false)
	securityE2EWriteSentinels(t, f.pages)
	pagesBefore := securityE2ESnapshotPagesTree(t, f.pages)
	body := securityE2EWebhookBody("push", "alice", "private", 11, `,"clone_url":"https://attacker.invalid/steal.git","private":false`)

	wrongSecret := f.deliver("push", "alice-hook", "bob-secret", "tenant-wrong-secret", body)
	if got, want := responseStatus(t, wrongSecret), http.StatusUnauthorized; got != want {
		t.Fatalf("wrong-secret status = %d, want %d", got, want)
	}
	idor := f.deliver("push", "bob-hook", "bob-secret", "tenant-idor", body)
	if got, want := responseStatus(t, idor), http.StatusForbidden; got != want {
		t.Fatalf("cross-tenant status = %d, want %d", got, want)
	}
	if got := securityE2EGitInvocations(t, f.gitMarker); len(got) != 0 {
		t.Fatalf("Git ran for rejected cross-tenant deliveries: %v", got)
	}
	securityE2EAssertPagesTreeUnchanged(t, pagesBefore, f.pages)
}

// This would fail if malformed or colliding repository metadata reached a
// destructive deployment or removal path after canonical API verification.
func TestSecurityE2EDestructivePathsLeaveEveryTenantUntouched(t *testing.T) {
	cases := []struct {
		name, owner, repo string
	}{
		{name: "empty", owner: "alice", repo: ""},
		{name: "dot", owner: "alice", repo: "."},
		{name: "dot dot", owner: "alice", repo: ".."},
		{name: "encoded slash", owner: "alice", repo: "%2foutside"},
		{name: "encoded backslash", owner: "alice", repo: "%5coutside"},
		{name: "unicode slash", owner: "alice", repo: "site\u2215outside"},
		{name: "mixed case collision", owner: "ALICE", repo: "site"},
		{name: "foreign pages domain", owner: "alice", repo: "alice.pages.foreign.test"},
	}
	for _, event := range []string{"push", "delete"} {
		for _, tc := range cases {
			t.Run(event+"/"+tc.name, func(t *testing.T) {
				f := newSecurityE2EFixture(t)
				repo := securityE2ECanonicalRepository(41, tc.owner, tc.repo, f.cloneOriginURL+"/safe/site.git", false)
				f.setCanonicalRepo(repo)
				sentinels := securityE2EWriteSentinels(t, f.pages)
				response := f.deliver(event, "alice-hook", "alice-secret", event+"-"+tc.name, securityE2EWebhookBody(event, tc.owner, tc.repo, 41, ""))
				if status := responseStatus(t, response); status < 400 || status >= 500 {
					t.Fatalf("status = %d, want rejected client request", status)
				}
				if got := securityE2EGitInvocations(t, f.gitMarker); len(got) != 0 {
					t.Fatalf("Git ran for rejected destructive path: %v", got)
				}
				securityE2EAssertSentinels(t, sentinels)
			})
		}
	}
}

// This would fail if a clone URL from the repository API could select the Git
// destination. Unsafe API response values must be ignored in favor of the
// configured public Gitea origin after repository identity verification.
func TestSecurityE2EIgnoresUnsafeRepositoryAPICloneURLs(t *testing.T) {
	unsafe := []struct {
		name string
		url  func(*securityE2EFixture) string
	}{
		{name: "file", url: func(_ *securityE2EFixture) string { return "file:///tmp/private.git" }},
		{name: "ssh", url: func(f *securityE2EFixture) string {
			return "ssh://" + strings.TrimPrefix(f.giteaServer.URL, "http://") + "/alice/site.git"
		}},
		{name: "git", url: func(f *securityE2EFixture) string {
			return "git://" + strings.TrimPrefix(f.giteaServer.URL, "http://") + "/alice/site.git"
		}},
		{name: "foreign port", url: func(_ *securityE2EFixture) string { return "https://127.0.0.1:444/alice/site.git" }},
		{name: "userinfo", url: func(f *securityE2EFixture) string {
			return "https://token@" + strings.TrimPrefix(f.giteaServer.URL, "http://") + "/alice/site.git"
		}},
		{name: "query", url: func(f *securityE2EFixture) string { return f.cloneOriginURL + "/alice/site.git?token=secret" }},
	}
	for _, tc := range unsafe {
		t.Run(tc.name, func(t *testing.T) {
			f := newSecurityE2EFixture(t)
			f.setCanonicalRepo(securityE2ECanonicalRepository(7, "alice", "site", tc.url(f), true))
			response := f.deliver("push", "alice-hook", "alice-secret", "transport-"+tc.name, securityE2EWebhookBody("push", "alice", "site", 7, ""))
			if got, want := responseStatus(t, response), http.StatusOK; got != want {
				t.Fatalf("status = %d, want %d", got, want)
			}
			if got := securityE2EGitInvocations(t, f.gitMarker); strings.Join(got, ",") != "clone" {
				t.Fatalf("Git invocations = %v, want clone using configured origin", got)
			}
		})
	}
}

// This would fail if a repository lookup followed a redirect to another
// origin, then trusted its response as though it were from configured Gitea.
func TestSecurityE2ERejectsRepositoryAPIRedirectBeforeGit(t *testing.T) {
	f := newSecurityE2EFixture(t)
	var foreignRedirectRequests atomic.Int64
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		foreignRedirectRequests.Add(1)
		_ = json.NewEncoder(w).Encode(securityE2ECanonicalRepository(7, "alice", "site", f.cloneOriginURL+"/alice/site.git", true))
	}))
	defer foreign.Close()
	f.gitea.mu.Lock()
	f.gitea.redirectURL = foreign.URL + "/api/v1/repos/alice/site"
	f.gitea.mu.Unlock()
	response := f.deliver("push", "alice-hook", "alice-secret", "transport-redirect", securityE2EWebhookBody("push", "alice", "site", 7, ""))
	status := responseStatus(t, response)
	if got := foreignRedirectRequests.Load(); got != 0 {
		t.Fatalf("foreign redirect endpoint received %d requests, want 0", got)
	}
	if got, want := status, http.StatusForbidden; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if got := securityE2EGitInvocations(t, f.gitMarker); len(got) != 0 {
		t.Fatalf("Git ran after repository API redirect: %v", got)
	}
}

// This would fail if a timed-out clone retained the global deployment slot or
// replaced the live site before it completed.
func TestSecurityE2ECloneTimeoutReleasesSlotAndPreservesLiveSite(t *testing.T) {
	f := newSecurityE2EFixture(t)
	f.addRepo(1, "alice", "site", false)
	f.addRepo(2, "bob", "site", false)
	aliceTarget, err := NewSiteTarget(f.pages, "alice", "site", "pages.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(aliceTarget.Path(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aliceTarget.Path(), "index.html"), []byte("old site"), 0600); err != nil {
		t.Fatal(err)
	}
	started := filepath.Join(t.TempDir(), "first-clone-started")
	f.service.cloneTimeout = 75 * time.Millisecond
	f.service.gitOps.gitBinary = securityE2EFirstCloneHangsThenSucceeds(t, f.gitMarker, started)

	firstDone := make(chan int, 1)
	go func() {
		response := f.deliver("push", "alice-hook", "alice-secret", "timeout-alice", securityE2EWebhookBody("push", "alice", "site", 1, ""))
		firstDone <- responseStatus(t, response)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("hanging clone never started")
		}
		time.Sleep(time.Millisecond)
	}
	second := f.deliver("push", "bob-hook", "bob-secret", "timeout-bob", securityE2EWebhookBody("push", "bob", "site", 2, ""))
	if got, want := responseStatus(t, second), http.StatusOK; got != want {
		t.Fatalf("queued deployment status = %d, want %d", got, want)
	}
	if got := <-firstDone; got != http.StatusInternalServerError {
		t.Fatalf("timed-out deployment status = %d, want %d", got, http.StatusInternalServerError)
	}
	if contents, err := os.ReadFile(filepath.Join(aliceTarget.Path(), "index.html")); err != nil || string(contents) != "old site" {
		t.Fatalf("timed-out clone changed Alice live site: %q, %v", contents, err)
	}
	if contents, err := os.ReadFile(filepath.Join(f.pages, "bob", "site", "index.html")); err != nil || string(contents) != "<h1>new site</h1>" {
		t.Fatalf("queued deployment did not publish Bob's site: %q, %v", contents, err)
	}
	if got := securityE2EGitInvocations(t, f.gitMarker); strings.Join(got, ",") != "hang,clone" {
		t.Fatalf("Git invocations = %v, want hanging clone then queued clone", got)
	}
}
