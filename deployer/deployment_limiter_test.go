package main

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This would fail if a clone subprocess were detached from the caller's
// deadline.
func TestCloneHonorsContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := runGitClone(ctx, fakeHangingGit(t), mustHTTPSURL(t, "https://gitea.example.com/alice/site.git"), filepath.Join(t.TempDir(), "repository"), "token")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
}

// This would fail if a full deployment limiter admitted another target before
// an existing deployment released its global slot.
func TestDeploymentLimiterRejectsWhenFull(t *testing.T) {
	limiter := NewDeploymentLimiter(1)
	release, err := limiter.Acquire(context.Background(), "alice/site")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := limiter.Acquire(ctx, "bob/site"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected saturation deadline, got %v", err)
	}
}

// This would fail if deployments for the same target could copy or replace
// concurrently despite available global capacity.
func TestDeploymentLimiterSerializesSameTarget(t *testing.T) {
	limiter := NewDeploymentLimiter(2)
	firstRelease, err := limiter.Acquire(context.Background(), "alice/site")
	if err != nil {
		t.Fatal(err)
	}
	defer firstRelease()

	entered := make(chan func(), 1)
	go func() {
		release, acquireErr := limiter.Acquire(context.Background(), "alice/site")
		if acquireErr == nil {
			entered <- release
		}
	}()

	select {
	case release := <-entered:
		release()
		t.Fatal("same target acquired while the first deployment was active")
	case <-time.After(25 * time.Millisecond):
	}
	firstRelease()

	select {
	case release := <-entered:
		release()
	case <-time.After(time.Second):
		t.Fatal("same-target deployment did not proceed after release")
	}
}

// This would fail if a waiter for an already-active target took a global slot
// before it obtained that target's lock, starving unrelated deployments.
func TestDeploymentLimiterSameTargetWaiterDoesNotConsumeGlobalSlot(t *testing.T) {
	limiter := NewDeploymentLimiter(2)
	firstRelease, err := limiter.Acquire(context.Background(), "alice/site")
	if err != nil {
		t.Fatal(err)
	}
	defer firstRelease()

	waiterDone := make(chan struct{})
	go func() {
		release, acquireErr := limiter.Acquire(context.Background(), "alice/site")
		if acquireErr == nil {
			release()
		}
		close(waiterDone)
	}()
	waitForTargetReference(t, limiter, "alice/site", 2)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	otherRelease, err := limiter.Acquire(ctx, "bob/site")
	if err != nil {
		t.Fatalf("unrelated target was starved by same-target waiter: %v", err)
	}
	otherRelease()
	firstRelease()
	select {
	case <-waiterDone:
	case <-time.After(time.Second):
		t.Fatal("same-target waiter did not complete after release")
	}
}

func waitForTargetReference(t *testing.T, limiter *DeploymentLimiter, target string, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		limiter.mu.Lock()
		got := 0
		if entry := limiter.targets[target]; entry != nil {
			got = entry.refs
		}
		limiter.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("target %q did not reach %d waiting references", target, want)
}

// This would fail if repository metadata were ignored until after a clone was
// started, allowing an over-limit repository to consume deployment resources.
func TestDeploymentServiceRejectsOversizedRepository(t *testing.T) {
	root := t.TempDir()
	target, err := NewSiteTarget(root, "alice", "site", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	service := NewDeploymentService(&Config{
		PagesDir:             root,
		MaxConcurrentDeploys: 1,
		AcquireTimeout:       time.Second,
		CloneTimeout:         time.Second,
		MaxRepositorySizeMB:  1,
		MaxSiteSizeMB:        1,
	})
	err = service.Deploy(context.Background(), VerifiedRepository{SizeBytes: 1024*1024 + 1}, target)
	if !errors.Is(err, ErrRepositoryTooLarge) {
		t.Fatalf("expected repository size rejection, got %v", err)
	}
}

// This would fail if untrusted checkout entries were skipped or replacement
// happened before content validation completed.
func TestSymlinkDeploymentRejectsAndPreservesPreviousSite(t *testing.T) {
	root := t.TempDir()
	target, err := NewSiteTarget(root, "alice", "site", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target.Path(), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target.Path(), "index.html"), []byte("old site"), 0644); err != nil {
		t.Fatal(err)
	}

	g := &GitOperations{pagesDir: root, maxSiteSizeMB: 1, gitBinary: fakeGitWithSymlink(t)}
	err = g.Deploy(context.Background(), VerifiedRepository{CloneURL: mustHTTPSURL(t, "https://gitea.example.com/alice/site.git")}, target)
	if err == nil {
		t.Fatal("symlinked checkout was deployed")
	}
	contents, readErr := os.ReadFile(filepath.Join(target.Path(), "index.html"))
	if readErr != nil || string(contents) != "old site" {
		t.Fatalf("previous site changed after rejected deployment: %q, %v", contents, readErr)
	}
}

// This would fail if site size were checked after replacement or only from
// untrusted metadata instead of while checkout bytes are copied to staging.
func TestOversizedSiteDeploymentPreservesPreviousSite(t *testing.T) {
	root := t.TempDir()
	target, err := NewSiteTarget(root, "alice", "site", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target.Path(), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target.Path(), "index.html"), []byte("old site"), 0644); err != nil {
		t.Fatal(err)
	}

	g := &GitOperations{pagesDir: root, maxSiteSizeMB: 1, gitBinary: fakeGitWithLargeSite(t)}
	err = g.Deploy(context.Background(), VerifiedRepository{CloneURL: mustHTTPSURL(t, "https://gitea.example.com/alice/site.git")}, target)
	if !errors.Is(err, ErrSiteTooLarge) {
		t.Fatalf("expected site size rejection, got %v", err)
	}
	contents, readErr := os.ReadFile(filepath.Join(target.Path(), "index.html"))
	if readErr != nil || string(contents) != "old site" {
		t.Fatalf("previous site changed after rejected deployment: %q, %v", contents, readErr)
	}
}

func fakeHangingGit(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "git")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nwhile :; do :; done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakeGitWithSymlink(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "git")
	contents := "#!/bin/sh\nfor arg do target=$arg; done\nmkdir -p \"$target\"\nprintf '<h1>new</h1>' > \"$target/index.html\"\nln -s /etc/passwd \"$target/leak\"\n"
	if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakeGitWithLargeSite(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "git")
	contents := "#!/bin/sh\nfor arg do target=$arg; done\nmkdir -p \"$target\"\ndd if=/dev/zero of=\"$target/large.bin\" bs=1048576 count=2 status=none\n"
	if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustHTTPSURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
