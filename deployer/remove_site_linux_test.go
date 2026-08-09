//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func (g *GitOperations) removeSiteWithAfterParentOpen(target SiteTarget, afterParentOpen func() error) error {
	if err := g.validateTarget(target); err != nil {
		return err
	}
	return removeSiteSecurelyWithAfterParentOpen(target, afterParentOpen)
}

// An attacker with the ability to rename a path must not be able to turn a
// validated target into a deletion of a directory outside the Pages root.
func TestRemoveSiteDoesNotFollowAncestorSymlinkSubstitutionAfterValidation(t *testing.T) {
	pagesRoot := t.TempDir()
	target, err := NewSiteTarget(pagesRoot, "alice", "site", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target.Path(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target.Path(), "index.html"), []byte("site"), 0600); err != nil {
		t.Fatal(err)
	}

	outside := t.TempDir()
	outsideSite := filepath.Join(outside, "site")
	if err := os.Mkdir(outsideSite, 0700); err != nil {
		t.Fatal(err)
	}
	outsideSentinel := filepath.Join(outsideSite, "sentinel")
	if err := os.WriteFile(outsideSentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	ownerPath := filepath.Join(pagesRoot, "alice")
	detachedOwner := filepath.Join(pagesRoot, "owner-before-substitution")
	gitOps := &GitOperations{pagesDir: pagesRoot}
	err = gitOps.removeSiteWithAfterParentOpen(target, func() error {
		if err := os.Rename(ownerPath, detachedOwner); err != nil {
			return err
		}
		return os.Symlink(outside, ownerPath)
	})
	if err != nil {
		t.Fatal(err)
	}

	if contents, err := os.ReadFile(outsideSentinel); err != nil || string(contents) != "keep" {
		t.Fatalf("outside sentinel changed: %q, %v", contents, err)
	}
	if _, err := os.Lstat(filepath.Join(detachedOwner, "site")); !os.IsNotExist(err) {
		t.Fatalf("original site was not removed through the retained directory descriptor: %v", err)
	}
}
