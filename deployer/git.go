package main

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const gitAskPassTokenEnv = "GITEA_PAGES_GIT_TOKEN"

// runGitClone runs a shallow HTTPS clone under the supplied deadline. Tokens
// are provided only to a short-lived askpass helper, never in argv or URLs.
func runGitClone(ctx context.Context, gitBinary string, cloneURL *url.URL, targetDir, token string) error {
	if cloneURL == nil || cloneURL.Scheme != "https" || cloneURL.Host == "" || cloneURL.User != nil || cloneURL.RawQuery != "" || cloneURL.Fragment != "" {
		return fmt.Errorf("invalid HTTPS clone URL")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, gitBinary,
		"-c", "protocol.file.allow=never",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.git.allow=never",
		"clone", "--branch", "gh-pages", "--single-branch", "--depth", "1", "--", cloneURL.String(), targetDir,
	)
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/tmp/gitea-pages-home",
		"LANG=C.UTF-8",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_LFS_SKIP_SMUDGE=1",
	}
	if token != "" {
		askPass, err := writeGitAskPass(filepath.Dir(targetDir))
		if err != nil {
			return err
		}
		defer os.Remove(askPass)
		cmd.Env = append(cmd.Env, "GIT_ASKPASS="+askPass, gitAskPassTokenEnv+"="+token)
	}

	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("git clone failed: %w, output: %s", err, SanitizeGitOutput(string(output)))
	}
	return nil
}

func writeGitAskPass(dir string) (string, error) {
	path := filepath.Join(dir, ".git-askpass")
	contents := "#!/bin/sh\ncase \"$1\" in\n  *Username*) printf '%s\\n' \"$" + gitAskPassTokenEnv + "\" ;;\n  *) printf '\\n' ;;\nesac\n"
	if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
		return "", fmt.Errorf("create git askpass helper: %w", err)
	}
	return path, nil
}

// GitOperations handles git clone and deployment operations
type GitOperations struct {
	pagesDir      string
	maxSiteSizeMB int64
	cloneTimeout  time.Duration
	gitBinary     string
	accessToken   string
	giteaClient   *GiteaClient
}

// NewGitOperations creates a new GitOperations instance
func NewGitOperations(config *Config) *GitOperations {
	var giteaClient *GiteaClient
	if config.GiteaAPIURL != "" && config.GiteaAccessToken != "" {
		giteaClient = NewGiteaClient(config.GiteaAPIURL, config.GiteaAccessToken)
	}

	return &GitOperations{
		pagesDir:      config.PagesDir,
		maxSiteSizeMB: config.MaxSiteSizeMB,
		cloneTimeout:  config.CloneTimeout,
		gitBinary:     "git",
		accessToken:   config.GiteaAccessToken,
		giteaClient:   giteaClient,
	}
}

// Deploy clones a verified repository into its validated target.
func (g *GitOperations) Deploy(ctx context.Context, repo VerifiedRepository, target SiteTarget) error {
	if repo.CloneURL == nil {
		return fmt.Errorf("verified repository clone URL is required")
	}
	return g.deploy(ctx, repo.CloneURL.String(), target, repo.Owner, repo.Name, repo.AccessToken)
}

// DeployWithToken is retained until DeploymentService replaces legacy webhook
// wiring. It accepts SiteTarget so it cannot introduce a raw destructive path.
func (g *GitOperations) DeployWithToken(cloneURL string, target SiteTarget, owner, repo string, userToken string) error {
	ctx := context.Background()
	if g.cloneTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.cloneTimeout)
		defer cancel()
	}
	return g.deploy(ctx, cloneURL, target, owner, repo, userToken)
}

func (g *GitOperations) deploy(ctx context.Context, cloneURL string, target SiteTarget, owner, repo, userToken string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := g.validateTarget(target); err != nil {
		return err
	}
	clone, err := url.Parse(cloneURL)
	if err != nil {
		return fmt.Errorf("parse clone URL: %w", err)
	}
	token := userToken
	if token == "" {
		token = g.accessToken
	}

	// Create temp directory for cloning
	tempDir, err := os.MkdirTemp("", "gitea-pages-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir) // Cleanup temp dir after deployment

	// Clone into an otherwise empty directory, leaving the short-lived askpass
	// helper outside the checkout so it cannot be deployed.
	checkoutDir := filepath.Join(tempDir, "repository")
	if err := runGitClone(ctx, g.gitCommand(), clone, checkoutDir, token); err != nil {
		return fmt.Errorf("failed to clone: %w", err)
	}

	// Staging is created beside the target so replacement remains on one
	// filesystem and never exposes a partially copied site.
	parentDir := filepath.Dir(target.Path())
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("failed to create parent dir: %w", err)
	}
	if err := g.validateTarget(target); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parentDir, ".staging-")
	if err != nil {
		return fmt.Errorf("create deployment staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	if err := g.copyFiles(checkoutDir, staging); err != nil {
		return fmt.Errorf("failed to copy files: %w", err)
	}
	return replaceSiteAtomically(staging, target)
}

func (g *GitOperations) gitCommand() string {
	if g.gitBinary == "" {
		return "git"
	}
	return g.gitBinary
}

// copyFiles copies files from source to destination
func (g *GitOperations) copyFiles(src, dst string) error {
	maxBytes := g.maxSiteSizeMB * 1024 * 1024
	var copied int64
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		// filepath.Walk presents Lstat metadata. Refuse any object whose
		// contents could resolve outside the checkout or have special I/O
		// behavior before creating anything in the staging directory.
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return fmt.Errorf("%w: privileged mode on %q", ErrUnsafeCheckoutContent, relPath)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink %q", ErrUnsafeCheckoutContent, relPath)
		}
		if relPath != "." && info.Name() == ".git" {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if relPath != "." && IsHiddenFile(info.Name()) {
			if !(info.Name() == ".nojekyll" && info.Mode().IsRegular()) &&
				!(info.Name() == ".well-known" && info.IsDir()) {
				return fmt.Errorf("%w: hidden entry %q", ErrUnsafeCheckoutContent, relPath)
			}
		}

		dstPath := filepath.Join(dst, relPath)
		if info.IsDir() {
			if err := os.MkdirAll(dstPath, 0755); err != nil {
				return err
			}
			return os.Chmod(dstPath, 0755)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: non-regular entry %q", ErrUnsafeCheckoutContent, relPath)
		}
		if info.Size() > maxBytes-copied {
			return fmt.Errorf("%w: more than %d bytes", ErrSiteTooLarge, maxBytes)
		}
		return copyFileBounded(path, dstPath, &copied, maxBytes)
	})
}

// copyFileBounded copies one regular file with its final deployment mode and
// accounts for bytes as they are written, rather than trusting metadata alone.
func copyFileBounded(src, dst string, copied *int64, maxBytes int64) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(&maxSiteWriter{writer: dstFile, copied: copied, maxBytes: maxBytes}, srcFile)
	if err != nil {
		return err
	}
	return os.Chmod(dst, 0644)
}

type maxSiteWriter struct {
	writer   io.Writer
	copied   *int64
	maxBytes int64
}

func (w *maxSiteWriter) Write(p []byte) (int, error) {
	remaining := w.maxBytes - *w.copied
	if remaining <= 0 {
		return 0, ErrSiteTooLarge
	}
	if int64(len(p)) > remaining {
		n, err := w.writer.Write(p[:int(remaining)])
		*w.copied += int64(n)
		if err != nil {
			return n, err
		}
		return n, ErrSiteTooLarge
	}
	n, err := w.writer.Write(p)
	*w.copied += int64(n)
	return n, err
}

// isAllowedHiddenFile checks if a hidden file should be allowed
func isAllowedHiddenFile(name string) bool {
	allowed := []string{".well-known", ".nojekyll"}
	for _, a := range allowed {
		if name == a || strings.HasPrefix(name, a+"/") {
			return true
		}
	}
	return false
}

// RemoveGitDir removes the .git directory
func RemoveGitDir(gitDir string) error {
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return nil // .git dir doesn't exist, nothing to do
	}
	return os.RemoveAll(gitDir)
}

func (g *GitOperations) validateTarget(target SiteTarget) error {
	pagesRoot, err := filepath.Abs(g.pagesDir)
	if err != nil {
		return fmt.Errorf("resolve pages root: %w", err)
	}
	if target.root == "" || target.root != pagesRoot {
		return fmt.Errorf("site target: %w", ErrUnsafeSiteTarget)
	}
	return target.validateExistingPath()
}

// CalculateDirSize calculates the total size of a directory in bytes
func CalculateDirSize(dirPath string) (int64, error) {
	var totalSize int64

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip symlinks (they should have been filtered out already)
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		if !info.IsDir() {
			totalSize += info.Size()
		}

		return nil
	})

	return totalSize, err
}

// RemoveSite removes one validated deployed site directory.
func (g *GitOperations) RemoveSite(target SiteTarget) error {
	if err := g.validateTarget(target); err != nil {
		return err
	}
	if _, err := os.Lstat(target.Path()); os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to remove
	} else if err != nil {
		return err
	}
	return os.RemoveAll(target.Path())
}
