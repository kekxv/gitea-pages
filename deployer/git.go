package main

import (
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

// Deploy clones repository and copies files to target path
func (g *GitOperations) Deploy(cloneURL, targetPath string, owner, repo string) error {
	// Pre-clone size check via Gitea API
	if g.giteaClient != nil {
		maxSizeBytes := g.maxSiteSizeMB * 1024 * 1024
		if err := g.giteaClient.CheckRepoSizeBeforeClone(owner, repo, maxSizeBytes); err != nil {
			return fmt.Errorf("pre-clone size check failed: %w", err)
		}
	}

	// Prepare authenticated clone URL
	authCloneURL, err := PrepareCloneURL(cloneURL, g.accessToken, g.sshKeyPath)
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
		return fmt.Errorf("site size %d MB exceeds maximum allowed %d MB (ref: https://docs.github.com/en/pages/getting-started-with-github-pages/about-github-pages#limits-on-use-of-github-pages)", sizeBytes/1024/1024, g.maxSiteSizeMB)
	}
	log.Printf("Site size: %d MB (limit: %d MB)", sizeBytes/1024/1024, g.maxSiteSizeMB)

	// Ensure target directory parent exists
	parentDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("failed to create parent dir: %w", err)
	}

	// Clean existing target directory if exists (old version cleanup)
	if err := CleanTargetDir(targetPath); err != nil {
		return fmt.Errorf("failed to clean target dir: %w", err)
	}

	// Copy files from temp to target
	if err := g.copyFiles(tempDir, targetPath); err != nil {
		return fmt.Errorf("failed to copy files: %w", err)
	}

	// Set secure permissions on target files
	if err := SetSecurePermissions(targetPath); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	return nil
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
	if err != nil {
		return fmt.Errorf("git clone failed: %w, output: %s", err, string(output))
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

// CleanTargetDir removes existing target directory contents
func CleanTargetDir(targetPath string) error {
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to clean
	}

	// Remove contents but keep directory for atomic replacement
	entries, err := os.ReadDir(targetPath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		path := filepath.Join(targetPath, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			return err
		}
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

// RemoveSite removes a deployed site directory
func RemoveSite(targetPath string) error {
	// Check if path exists
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to remove
	}

	// Security: Verify the path is within pages directory
	// This prevents accidental deletion of system files
	if !isSafePath(targetPath) {
		return fmt.Errorf("unsafe path detected: %s", targetPath)
	}

	// Remove the entire directory
	return os.RemoveAll(targetPath)
}

// isSafePath checks if the path is within allowed pages directory
func isSafePath(path string) bool {
	// Normalize path
	normalized := filepath.Clean(path)

	// Check for path traversal
	if strings.Contains(normalized, "..") {
		return false
	}

	// Must be absolute path starting with pages directory prefix
	// This is a basic check; in production you'd want more rigorous validation
	if !strings.HasPrefix(normalized, "/var/www/pages/") {
		return false
	}

	return true
}