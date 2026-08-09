# Descriptor-Relative Site Deletion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete a validated site without resolving an attacker-controlled pathname after validation.

**Architecture:** On Linux, retain trusted `openat2` descriptors for the Pages root and owner directory, then rename the requested leaf into a private tombstone name through that owner descriptor. Recursively remove only the tombstone reached through `/proc/self/fd/<owner fd>`, whose descriptor continues to reference the vetted directory even if a path ancestor is substituted. Non-Linux builds return an explicit unsupported error rather than falling back to path-based deletion.

**Tech Stack:** Go 1.26, `golang.org/x/sys/unix`, Linux `openat2`/`renameat`.

## Global Constraints

- Preserve existing delete-webhook response semantics: deletion errors are logged by the worker and the webhook returns its current success response.
- Do not use `os.RemoveAll` on `SiteTarget.Path()` or another attacker-re-resolved target pathname.
- Refuse symlinked, group-writable, world-writable, or untrusted Pages root/owner directories.
- Return explicit unsupported behavior on non-Linux.

---

### Task 1: Define the post-validation symlink-substitution regression

**Files:** `deployer/site_target_test.go`

**Interfaces:** Consumes `GitOperations.RemoveSite(target SiteTarget) error`; produces a Linux race regression showing target/owner substitution cannot delete an outside sentinel.

- [ ] **Step 1: Write the failing test**

```go
func TestRemoveSiteDoesNotFollowSymlinkSubstitutionAfterValidation(t *testing.T) {
	// Construct SiteTarget while root/owner/target are ordinary directories.
	// Concurrently replace owner or target with a symlink to outside while
	// calling RemoveSite repeatedly; outside/sentinel must remain "keep".
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker run --rm -v "$PWD/deployer:/src" -w /src golang:1.26 go test -run TestRemoveSiteDoesNotFollowSymlinkSubstitutionAfterValidation -count=1 -v`

Expected: FAIL because `RemoveSite` validates then calls `os.RemoveAll(target.Path())`.

### Task 2: Implement descriptor-relative deletion and unsupported fallback

**Files:** `deployer/git.go`, `deployer/atomic_replace_linux.go`, `deployer/atomic_replace_unsupported.go`, `deployer/atomic_replace.go`

**Interfaces:** Produces `removeSiteSecurely(target SiteTarget) error` and `ErrSecureDeletionUnsupported` on non-Linux.

- [ ] **Step 1: Write minimal implementation**

```go
func (g *GitOperations) RemoveSite(target SiteTarget) error {
	if err := g.validateTarget(target); err != nil { return err }
	return removeSiteSecurely(target)
}
```

- [ ] **Step 2: Run focused tests and the full suite**

Run: `docker run --rm -v "$PWD/deployer:/src" -w /src golang:1.26 go test ./...`

Expected: PASS, including outside sentinel preservation.

- [ ] **Step 3: Commit**

Stage the changed Go files and commit with `fix: delete sites through trusted directory descriptors`.
