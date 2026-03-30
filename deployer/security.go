package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SetSecurePermissions sets restrictive permissions on files and directories
// Files: 0644 (readable by all, writable by owner)
// Dirs: 0755 (readable/accessible by all, writable by owner)
func SetSecurePermissions(rootPath string) error {
	return filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip symlinks (they should have been filtered out already)
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		var newMode os.FileMode
		if info.IsDir() {
			newMode = 0755
		} else {
			newMode = 0644
		}

		// Remove execute permission from files for security
		return os.Chmod(path, newMode)
	} )
}

// DetectSymlinks scans directory for symlinks and returns list of them
func DetectSymlinks(rootPath string) ([]string, error) {
	var symlinks []string

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.Mode()&os.ModeSymlink != 0 {
			symlinks = append(symlinks, path)
		}

		return nil
	} )

	return symlinks, err
}

// ValidatePath ensures path doesn't contain traversal attempts and is within pages directory
func ValidatePath(path string, pagesDir string) error {
	// Clean and get absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	absPagesDir, err := filepath.Abs(pagesDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute pages dir: %w", err)
	}

	// Ensure path is within pages directory
	rel, err := filepath.Rel(absPagesDir, absPath)
	if err != nil {
		return fmt.Errorf("failed to get relative path: %w", err)
	}

	if strings.HasPrefix(rel, "..") || rel == ".." {
		return fmt.Errorf("path is outside pages directory: %s", path)
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("path contains null byte")
	}

	return nil
}

// SanitizePathComponent removes dangerous characters from path components (usernames, repo names)
func SanitizePathComponent(name string) string {
	// Only allow alphanumeric, hyphens, underscores and dots
	reg := regexp.MustCompile(`[^a-zA-Z0-9\-\_\.]`)
	sanitized := reg.ReplaceAllString(name, "")

	// Remove path traversal attempts
	sanitized = strings.ReplaceAll(sanitized, "..", "")
	
	// Remove leading/trailing dots and spaces
	sanitized = strings.TrimSpace(sanitized)
	sanitized = strings.Trim(sanitized, ".")

	return sanitized
}

// gitTokenRegex masks tokens in git URLs (e.g., https://TOKEN@host/ -> https://***@host/)
var gitTokenRegex = regexp.MustCompile(`(https?://)([^@/]+)(@)`)

// SanitizeGitOutput masks sensitive tokens in git command output
func SanitizeGitOutput(output string) string {
	return gitTokenRegex.ReplaceAllString(output, "$1***$3")
}

// IsHiddenFile checks if a file is hidden (starts with .)
func IsHiddenFile(name string) bool {
	return strings.HasPrefix(name, ".") && name != "." && name != ".."
}

// ShouldRejectFile determines if a file should be rejected for security reasons
func ShouldRejectFile(path string, info os.FileInfo) bool {
	// Reject symlinks
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}

	// Reject hidden files (except allowed ones)
	name := info.Name()
	if IsHiddenFile(name) && !isAllowedHiddenFile(name) {
		return true
	}

	// Reject files in .git directory
	if strings.Contains(path, "/.git/") || strings.HasSuffix(path, "/.git") {
		return true
	}

	return false
}