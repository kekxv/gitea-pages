package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewSiteTargetNeverReturnsPagesRoot(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct{ owner, repo string }{{"..", ".."}, {"", "site"}, {"alice", ""}, {"a/b", "site"}} {
		target, err := NewSiteTarget(root, tc.owner, tc.repo, "example.com")
		if err == nil || target.Path() == root {
			t.Fatalf("unsafe target accepted: %#v", tc)
		}
	}
}

func TestNewSiteTargetRejectsInvalidComponents(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name, owner, repo, domain string
	}{
		{"dot owner", ".", "site", "example.com"},
		{"embedded traversal", "ali..ce", "site", "example.com"},
		{"leading punctuation", "-alice", "site", "example.com"},
		{"space", "alice", "my site", "example.com"},
		{"path separator", "alice", "a/b", "example.com"},
		{"invalid domain", "alice", "site", "example..com"},
		{"too long", "alice", strings.Repeat("a", 101), "example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSiteTarget(root, tc.owner, tc.repo, tc.domain); err == nil {
				t.Fatal("invalid path component was accepted")
			}
		})
	}
}

func TestRootRepositoryMatchIsExact(t *testing.T) {
	root := t.TempDir()
	if _, err := NewSiteTarget(root, "alice", "alice.pages.evil.com", "example.com"); err == nil {
		t.Fatal("foreign Pages domain repository was accepted")
	}
}

func TestNewSiteTargetUsesOnlyExactRootRepositoryNames(t *testing.T) {
	root := t.TempDir()
	for _, repo := range []string{"alice", "ALICE.PAGES.EXAMPLE.COM"} {
		target, err := NewSiteTarget(root, "Alice", repo, "Example.COM")
		if err != nil {
			t.Fatalf("NewSiteTarget(%q): %v", repo, err)
		}
		if !target.IsRoot() {
			t.Fatalf("repository %q did not select the root site", repo)
		}
		if got, want := target.Path(), filepath.Join(root, "alice", "_root"); got != want {
			t.Fatalf("target path = %q, want %q", got, want)
		}
	}
}

func TestNewSiteTargetRejectsSymlinkedTargetAncestors(t *testing.T) {
	for _, tc := range []struct{ name string }{{"owner"}, {"target"}} {
		t.Run(tc.name, func(t *testing.T) {
			caseRoot := t.TempDir()
			caseOutside := t.TempDir()
			if err := os.WriteFile(filepath.Join(caseRoot, "pages-root-sentinel"), []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(caseRoot, "neighbor"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(caseRoot, "neighbor", "sentinel"), []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.name == "owner" {
				if err := os.Symlink(caseOutside, filepath.Join(caseRoot, "alice")); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(filepath.Join(caseRoot, "alice"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(caseOutside, filepath.Join(caseRoot, "alice", "site")); err != nil {
					t.Fatal(err)
				}
			}

			if _, err := NewSiteTarget(caseRoot, "alice", "site", "example.com"); err == nil {
				t.Fatal("symlinked target was accepted")
			}
			if contents, err := os.ReadFile(filepath.Join(caseRoot, "pages-root-sentinel")); err != nil || string(contents) != "keep" {
				t.Fatalf("pages root sentinel changed: %q, %v", contents, err)
			}
			if contents, err := os.ReadFile(filepath.Join(caseRoot, "neighbor", "sentinel")); err != nil || string(contents) != "keep" {
				t.Fatalf("neighbor sentinel changed: %q, %v", contents, err)
			}
		})
	}
}

func TestNewSiteTargetRejectsSymlinkedPagesRoot(t *testing.T) {
	pagesRoot := t.TempDir()
	link := filepath.Join(t.TempDir(), "pages")
	if err := os.Symlink(pagesRoot, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSiteTarget(link, "alice", "site", "example.com"); err == nil {
		t.Fatal("symlinked pages root was accepted")
	}
}

func TestNewSiteTargetRejectsPagesRootWithSymlinkedAncestor(t *testing.T) {
	base := t.TempDir()
	physicalParent := filepath.Join(base, "physical")
	pagesRoot := filepath.Join(physicalParent, "pages")
	if err := os.MkdirAll(pagesRoot, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(physicalParent, alias); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(pagesRoot, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewSiteTarget(filepath.Join(alias, "pages"), "alice", "site", "example.com"); err == nil {
		t.Fatal("pages root beneath a symlinked ancestor was accepted")
	}
	if contents, err := os.ReadFile(sentinel); err != nil || string(contents) != "keep" {
		t.Fatalf("pages root sentinel changed: %q, %v", contents, err)
	}
}

func TestRemoveSiteDeletesOnlyItsValidatedTarget(t *testing.T) {
	root := t.TempDir()
	target, err := NewSiteTarget(root, "alice", "site", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target.Path(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target.Path(), "index.html"), []byte("site"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pages-root-sentinel"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "neighbor"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "neighbor", "sentinel"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	gitOps := &GitOperations{pagesDir: root}
	if err := gitOps.RemoveSite(target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target.Path()); !os.IsNotExist(err) {
		t.Fatalf("site target still exists: %v", err)
	}
	for _, sentinel := range []string{filepath.Join(root, "pages-root-sentinel"), filepath.Join(root, "neighbor", "sentinel")} {
		contents, err := os.ReadFile(sentinel)
		if err != nil || string(contents) != "keep" {
			t.Fatalf("sentinel %q changed: %q, %v", sentinel, contents, err)
		}
	}
}

func TestRemoveSiteRefusesAnAncestorChangedToASymlink(t *testing.T) {
	root := t.TempDir()
	target, err := NewSiteTarget(root, "alice", "site", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "sentinel"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "alice")); err != nil {
		t.Fatal(err)
	}

	gitOps := &GitOperations{pagesDir: root}
	if err := gitOps.RemoveSite(target); err == nil {
		t.Fatal("RemoveSite accepted a target whose owner became a symlink")
	}
	if contents, err := os.ReadFile(filepath.Join(outside, "sentinel")); err != nil || string(contents) != "keep" {
		t.Fatalf("outside sentinel changed: %q, %v", contents, err)
	}
}

func TestRemoveSiteRefusesPagesRootAncestorChangedToASymlink(t *testing.T) {
	base := t.TempDir()
	physicalParent := filepath.Join(base, "physical")
	pagesRoot := filepath.Join(physicalParent, "pages")
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
	if err := os.WriteFile(filepath.Join(pagesRoot, "pages-root-sentinel"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	movedParent := filepath.Join(base, "moved-physical")
	if err := os.Rename(physicalParent, movedParent); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(movedParent, physicalParent); err != nil {
		t.Fatal(err)
	}

	gitOps := &GitOperations{pagesDir: pagesRoot}
	if err := gitOps.RemoveSite(target); err == nil {
		t.Fatal("RemoveSite accepted a Pages root with a symlinked ancestor")
	}
	for path, want := range map[string]string{
		filepath.Join(movedParent, "pages", "alice", "site", "index.html"): "site",
		filepath.Join(movedParent, "pages", "pages-root-sentinel"):         "keep",
	} {
		if contents, err := os.ReadFile(path); err != nil || string(contents) != want {
			t.Fatalf("preserved content %q = %q, %v; want %q", path, contents, err, want)
		}
	}
}

func TestRemoveSiteRefusesTargetFromAnotherPagesRoot(t *testing.T) {
	target, err := NewSiteTarget(t.TempDir(), "alice", "site", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	gitOps := &GitOperations{pagesDir: t.TempDir()}
	if err := gitOps.RemoveSite(target); err == nil {
		t.Fatal("RemoveSite accepted a SiteTarget from another pages root")
	}
}

func TestAtomicReplaceReplacesOnlyTheValidatedTarget(t *testing.T) {
	root := t.TempDir()
	target, err := NewSiteTarget(root, "alice", "site", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target.Path(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target.Path(), "old.html"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	staging, err := os.MkdirTemp(filepath.Dir(target.Path()), ".staging-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "index.html"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pages-root-sentinel"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := replaceSiteAtomically(staging, target); err != nil {
		t.Fatal(err)
	}
	if contents, err := os.ReadFile(filepath.Join(target.Path(), "index.html")); err != nil || string(contents) != "new" {
		t.Fatalf("replacement contents = %q, %v", contents, err)
	}
	if _, err := os.Lstat(filepath.Join(target.Path(), "old.html")); !os.IsNotExist(err) {
		t.Fatalf("old site file still exists: %v", err)
	}
	if contents, err := os.ReadFile(filepath.Join(root, "pages-root-sentinel")); err != nil || string(contents) != "keep" {
		t.Fatalf("pages root sentinel changed: %q, %v", contents, err)
	}
}

// This would fail if a group- or world-writable Pages root or owner directory
// could be changed between validation and the name exchange.
func TestAtomicReplaceRejectsWritablePublicationDirectories(t *testing.T) {
	for _, tc := range []struct {
		name         string
		makeWritable func(root string, target SiteTarget) error
	}{
		{
			name: "pages root",
			makeWritable: func(root string, _ SiteTarget) error {
				return os.Chmod(root, 0777)
			},
		},
		{
			name: "owner directory",
			makeWritable: func(_ string, target SiteTarget) error {
				return os.Chmod(filepath.Dir(target.Path()), 0777)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			target, err := NewSiteTarget(root, "alice", "site", "example.com")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(target.Path(), 0755); err != nil {
				t.Fatal(err)
			}
			staging, err := os.MkdirTemp(filepath.Dir(target.Path()), ".staging-")
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.makeWritable(root, target); err != nil {
				t.Fatal(err)
			}

			err = replaceSiteAtomically(staging, target)
			if !errors.Is(err, ErrUnsafeSiteTarget) {
				t.Fatalf("expected unsafe publication directory rejection, got %v", err)
			}
		})
	}
}

// This would fail if an existing target were first moved aside before the new
// site is published: a failed exchange must leave both paths unchanged.
func TestAtomicReplaceLeavesLiveSiteUntouchedWhenExchangeFails(t *testing.T) {
	root := t.TempDir()
	target, err := NewSiteTarget(root, "alice", "site", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target.Path(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target.Path(), "old.html"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	staging, err := os.MkdirTemp(filepath.Dir(target.Path()), ".staging-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "index.html"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}

	err = replaceSiteAtomicallyWithExchange(staging, target, func(_ int, _, _ string) error {
		return errors.New("injected exchange failure")
	})
	if err == nil {
		t.Fatal("replacement unexpectedly succeeded")
	}
	if contents, err := os.ReadFile(filepath.Join(target.Path(), "old.html")); err != nil || string(contents) != "old" {
		t.Fatalf("previous site was not restored: %q, %v", contents, err)
	}
	if contents, err := os.ReadFile(filepath.Join(staging, "index.html")); err != nil || string(contents) != "new" {
		t.Fatalf("staging site changed after failed install: %q, %v", contents, err)
	}
}
