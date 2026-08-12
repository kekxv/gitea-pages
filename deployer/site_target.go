package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	ErrInvalidPathComponent = errors.New("invalid path component")
	ErrUnsafeSiteTarget     = errors.New("unsafe site target")
)

var giteaPathComponent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// SiteTarget is the only representation of a deployed site path accepted by
// destructive filesystem operations.
type SiteTarget struct {
	root, owner, repo, path string
	rootSite                bool
}

func (t SiteTarget) Path() string { return t.path }

func (t SiteTarget) IsRoot() bool { return t.rootSite }

func validateComponent(kind, value string) (string, error) {
	if value == "." || value == ".." || !giteaPathComponent.MatchString(value) || strings.Contains(value, "..") {
		return "", fmt.Errorf("%s: %w", kind, ErrInvalidPathComponent)
	}
	return strings.ToLower(value), nil
}

// NewSiteTarget validates canonical Gitea repository metadata and constructs
// a two-component path below root. Existing symlinks in that path are refused.
func NewSiteTarget(root, owner, repo, domain string) (SiteTarget, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return SiteTarget{}, fmt.Errorf("resolve pages root: %w", err)
	}
	owner, err = validateComponent("owner", owner)
	if err != nil {
		return SiteTarget{}, err
	}
	repo, err = validateComponent("repository", repo)
	if err != nil {
		return SiteTarget{}, err
	}
	domain, err = validateComponent("domain", domain)
	if err != nil {
		return SiteTarget{}, err
	}

	// Repository names matching owner.<complete Pages domain> select the
	// account root site. A similarly named foreign domain must never create a
	// second destructive path below the same owner directory.
	rootRepository := owner + "." + domain
	if strings.HasPrefix(repo, owner+".pages.") && repo != rootRepository {
		return SiteTarget{}, fmt.Errorf("repository: %w", ErrInvalidPathComponent)
	}

	rootSite := repo == owner || repo == rootRepository
	leaf := repo
	if rootSite {
		leaf = "_root"
	}
	path := filepath.Join(rootAbs, owner, leaf)
	rel, err := filepath.Rel(rootAbs, path)
	if err != nil {
		return SiteTarget{}, fmt.Errorf("resolve site target: %w", err)
	}
	components := strings.Split(rel, string(filepath.Separator))
	if rel == "." || filepath.IsAbs(rel) || len(components) != 2 || components[0] == "." || components[1] == "." || components[0] == ".." || components[1] == ".." {
		return SiteTarget{}, fmt.Errorf("site target: %w", ErrUnsafeSiteTarget)
	}

	target := SiteTarget{root: rootAbs, owner: owner, repo: repo, path: path, rootSite: rootSite}
	if err := target.validateExistingPath(); err != nil {
		return SiteTarget{}, err
	}
	return target, nil
}

func (t SiteTarget) validateExistingPath() error {
	if err := rejectSymlinkedAncestors(t.root); err != nil {
		return err
	}
	for _, path := range []string{filepath.Join(t.root, t.owner), t.path} {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect site target: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("site target %q: %w", path, ErrUnsafeSiteTarget)
		}
	}
	return nil
}

func rejectSymlinkedAncestors(path string) error {
	var ancestors []string
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		ancestors = append(ancestors, current)
		if parent := filepath.Dir(current); parent == current {
			break
		}
	}
	for i := len(ancestors) - 1; i >= 0; i-- {
		info, err := os.Lstat(ancestors[i])
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect pages root ancestor: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("pages root ancestor %q: %w", ancestors[i], ErrUnsafeSiteTarget)
		}
	}
	return nil
}
