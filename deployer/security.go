package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	})
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
	})

	return symlinks, err
}

// ValidatePath ensures path doesn't contain traversal attempts
func ValidatePath(path string) error {
	// Check for path traversal
	if strings.Contains(path, "..") {
		return fmt.Errorf("path contains traversal sequence: %s", path)
	}

	// Check for absolute path attempts in relative context
	if strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "/var/www/pages/") {
		return fmt.Errorf("invalid absolute path: %s", path)
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("path contains null byte")
	}

	return nil
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