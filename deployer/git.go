package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GitOperations handles git clone and deployment operations
type GitOperations struct {
	pagesDir      string
	maxSiteSizeMB int64
	sshKeyPath    string
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
		sshKeyPath:    config.GiteaSSHKeyPath,
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
	return g.deploy(context.Background(), cloneURL, target, owner, repo, userToken)
}

func (g *GitOperations) deploy(ctx context.Context, cloneURL string, target SiteTarget, owner, repo, userToken string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := g.validateTarget(target); err != nil {
		return err
	}
	// Pre-clone size check via Gitea API
	if g.giteaClient != nil {
		maxSizeBytes := g.maxSiteSizeMB * 1024 * 1024
		if err := g.giteaClient.CheckRepoSizeBeforeClone(owner, repo, maxSizeBytes); err != nil {
			return fmt.Errorf("pre-clone size check failed: %w", err)
		}
	}

	// Prepare authenticated clone URL
	token := userToken
	if token == "" {
		token = g.accessToken
	}
	authCloneURL, err := PrepareCloneURL(cloneURL, token, g.sshKeyPath)
	if err != nil {
		return fmt.Errorf("failed to prepare clone URL: %w", err)
	}

	// Setup SSH key if configured
	if g.sshKeyPath != "" {
		if err := SetupSSHKey(g.sshKeyPath); err != nil {
			return fmt.Errorf("failed to setup SSH key: %w", err)
		}
	}

	// Create temp directory for cloning
	tempDir, err := os.MkdirTemp("", "gitea-pages-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir) // Cleanup temp dir after deployment

	// Clone repository with shallow clone
	if err := g.cloneRepo(authCloneURL, tempDir, g.sshKeyPath); err != nil {
		return fmt.Errorf("failed to clone: %w", err)
	}

	// Remove .git directory from cloned repo
	gitDir := filepath.Join(tempDir, ".git")
	if err := RemoveGitDir(gitDir); err != nil {
		log.Printf("Warning: failed to remove .git dir: %v", err)
	}

	// Security: Check site size before deployment
	sizeBytes, err := CalculateDirSize(tempDir)
	if err != nil {
		return fmt.Errorf("failed to calculate size: %w", err)
	}
	maxSizeBytes := g.maxSiteSizeMB * 1024 * 1024
	if sizeBytes > maxSizeBytes {
		return fmt.Errorf("site size %d MB exceeds maximum allowed %d MB", sizeBytes/1024/1024, g.maxSiteSizeMB)
	}
	log.Printf("Site size: %d MB (limit: %d MB)", sizeBytes/1024/1024, g.maxSiteSizeMB)

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
	if err := g.copyFiles(tempDir, staging); err != nil {
		return fmt.Errorf("failed to copy files: %w", err)
	}
	if err := SetSecurePermissions(staging); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}
	return replaceSiteAtomically(staging, target)
}

// cloneRepo performs a shallow clone of the repository
func (g *GitOperations) cloneRepo(cloneURL, targetDir, sshKeyPath string) error {
	// Security: Sanitize clone URL to prevent command injection
	if strings.Contains(cloneURL, "&&") || strings.Contains(cloneURL, "||") {
		return fmt.Errorf("invalid clone URL: contains dangerous characters")
	}

	cmd := exec.Command("git", "clone",
		"--branch", "gh-pages",
		"--single-branch",
		"--depth", "1",
		"--",
		cloneURL,
		targetDir,
	)

	// Setup environment for SSH or HTTPS authentication
	cmdEnv := []string{
		"GIT_TERMINAL_PROMPT=0", // Disable interactive prompts
		"HOME=/tmp",
	}

	// Configure SSH key if provided
	if sshKeyPath != "" {
		cmdEnv = append(cmdEnv,
			fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null", sshKeyPath),
		)
	}

	cmd.Env = cmdEnv

	output, err := cmd.CombinedOutput()
	sanitizedOutput := SanitizeGitOutput(string(output))
	if err != nil {
		return fmt.Errorf("git clone failed: %w, output: %s", err, sanitizedOutput)
	}

	return nil
}

// copyFiles copies files from source to destination
func (g *GitOperations) copyFiles(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dst, relPath)

		// Security: Check for symlinks and reject them
		if info.Mode()&os.ModeSymlink != 0 {
			log.Printf("Warning: rejecting symlink at %s", path)
			return nil // Skip symlinks
		}

		// Security: Reject hidden files (except .html, .css etc which are web files)
		if strings.HasPrefix(info.Name(), ".") && !isAllowedHiddenFile(info.Name()) {
			log.Printf("Warning: rejecting hidden file %s", path)
			return nil
		}

		if info.IsDir() {
			return os.MkdirAll(dstPath, 0755)
		}

		return copyFile(path, dstPath, info.Mode())
	})
}

// copyFile copies a single file
func copyFile(src, dst string, mode os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// isAllowedHiddenFile checks if a hidden file should be allowed
func isAllowedHiddenFile(name string) bool {
	// Allow common web hidden files like .htaccess, .well-known
	allowed := []string{".htaccess", ".well-known", ".nojekyll", ".gitignore"}
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

func replaceSiteAtomically(staging string, target SiteTarget) error {
	return replaceSiteAtomicallyWithRename(staging, target, os.Rename)
}

func replaceSiteAtomicallyWithRename(staging string, target SiteTarget, rename func(string, string) error) error {
	if err := target.validateExistingPath(); err != nil {
		return err
	}
	parent := filepath.Dir(target.Path())
	stagingAbs, err := filepath.Abs(staging)
	if err != nil {
		return fmt.Errorf("resolve deployment staging directory: %w", err)
	}
	if filepath.Dir(stagingAbs) != parent {
		return fmt.Errorf("staging directory: %w", ErrUnsafeSiteTarget)
	}
	stagingInfo, err := os.Lstat(stagingAbs)
	if err != nil {
		return fmt.Errorf("inspect deployment staging directory: %w", err)
	}
	if !stagingInfo.IsDir() || stagingInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("staging directory: %w", ErrUnsafeSiteTarget)
	}

	if _, err := os.Lstat(target.Path()); os.IsNotExist(err) {
		return rename(stagingAbs, target.Path())
	} else if err != nil {
		return err
	}
	backup, err := os.MkdirTemp(parent, ".previous-")
	if err != nil {
		return fmt.Errorf("create previous-site path: %w", err)
	}
	if err := os.Remove(backup); err != nil {
		return fmt.Errorf("prepare previous-site path: %w", err)
	}
	if err := rename(target.Path(), backup); err != nil {
		return fmt.Errorf("move previous site: %w", err)
	}
	if err := rename(stagingAbs, target.Path()); err != nil {
		if restoreErr := rename(backup, target.Path()); restoreErr != nil {
			return fmt.Errorf("install replacement: %w (restore previous site: %v)", err, restoreErr)
		}
		return fmt.Errorf("install replacement: %w", err)
	}
	if err := os.RemoveAll(backup); err != nil {
		return fmt.Errorf("remove previous site: %w", err)
	}
	return nil
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
