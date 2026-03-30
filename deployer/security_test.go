package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetSecurePermissions(t *testing.T) {
	// Create temp directory with files and subdirectories
	tempDir := t.TempDir()

	// Create files with various permissions
	file1 := filepath.Join(tempDir, "file1.txt")
	if err := os.WriteFile(file1, []byte("test"), 0777); err != nil {
		t.Fatalf("Failed to create file1: %v", err)
	}

	file2 := filepath.Join(tempDir, "file2.txt")
	if err := os.WriteFile(file2, []byte("test"), 0755); err != nil {
		t.Fatalf("Failed to create file2: %v", err)
	}

	// Create subdirectory
	subDir := filepath.Join(tempDir, "subdir")
	if err := os.Mkdir(subDir, 0777); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	// Apply secure permissions
	err := SetSecurePermissions(tempDir)
	if err != nil {
		t.Errorf("SetSecurePermissions failed: %v", err)
	}

	// Check file permissions
	info1, err := os.Stat(file1)
	if err != nil {
		t.Fatalf("Failed to stat file1: %v", err)
	}
	if info1.Mode() != 0644 {
		t.Errorf("File1 permission should be 0644, got %v", info1.Mode())
	}

	info2, err := os.Stat(file2)
	if err != nil {
		t.Fatalf("Failed to stat file2: %v", err)
	}
	if info2.Mode() != 0644 {
		t.Errorf("File2 permission should be 0644, got %v", info2.Mode())
	}

	// Check directory permission
	dirInfo, err := os.Stat(subDir)
	if err != nil {
		t.Fatalf("Failed to stat subdir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0755 {
		t.Errorf("Subdir permission should be 0755, got %v", dirInfo.Mode().Perm())
	}
}

func TestDetectSymlinks(t *testing.T) {
	tempDir := t.TempDir()

	// Create regular file
	file := filepath.Join(tempDir, "regular.txt")
	if err := os.WriteFile(file, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Create symlink
	symlink := filepath.Join(tempDir, "symlink")
	if err := os.Symlink(file, symlink); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	// Detect symlinks
	symlinks, err := DetectSymlinks(tempDir)
	if err != nil {
		t.Errorf("DetectSymlinks failed: %v", err)
	}

	if len(symlinks) != 1 {
		t.Errorf("Expected 1 symlink, got %d", len(symlinks))
	}

	if symlinks[0] != symlink {
		t.Errorf("Expected symlink path %s, got %s", symlink, symlinks[0])
	}
}

func TestValidatePath(t *testing.T) {
	pagesDir := "/var/www/pages"
	tests := []struct {
		path     string
		hasError bool
	}{
		{"/var/www/pages/user/repo", false},
		{"/var/www/pages/user/repo/file.txt", false},
		{"/etc/passwd", true},                        // outside allowed path
		{"/var/www/pages/user/../../etc/passwd", true}, // path traversal
		{"/var/www/pages/../pages/user", false},       // technically inside but cleaned
		{"/var/www/pages/user\x00/repo", true},       // null byte
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := ValidatePath(tt.path, pagesDir)
			if tt.hasError && err == nil {
				t.Errorf("ValidatePath(%s) should return error", tt.path)
			}
			if !tt.hasError && err != nil {
				t.Errorf("ValidatePath(%s) should not return error: %v", tt.path, err)
			}
		})
	}
}

func TestSanitizePathComponent(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"user123", "user123"},
		{"user/../admin", "useradmin"},
		{"repo.git", "repo.git"},
		{"  spaces  ", "spaces"},
		{"special!@#$%^&*()chars", "specialchars"},
		{"..", ""},
		{".../", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := SanitizePathComponent(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizePathComponent(%s) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeGitOutput(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			"Cloning into 'temp'...\nfatal: unable to access 'https://my-token@gitea.com/user/repo.git/': 401",
			"Cloning into 'temp'...\nfatal: unable to access 'https://***@gitea.com/user/repo.git/': 401",
		},
		{
			"error: https://another-token:password@host.com/path",
			"error: https://***@host.com/path",
		},
		{
			"No token here: https://public-repo.com/",
			"No token here: https://public-repo.com/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := SanitizeGitOutput(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeGitOutput() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsHiddenFile(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{".git", true},
		{".env", true},
		{".htaccess", true},
		{"normal.txt", false},
		{".", false},
		{"..", false},
		{"file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsHiddenFile(tt.name)
			if result != tt.expected {
				t.Errorf("IsHiddenFile(%s) = %v, expected %v", tt.name, result, tt.expected)
			}
		})
	}
}

func TestShouldRejectFile(t *testing.T) {
	tempDir := t.TempDir()

	// Create regular file
	regularFile := filepath.Join(tempDir, "regular.txt")
	if err := os.WriteFile(regularFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create regular file: %v", err)
	}

	// Create symlink
	targetFile := filepath.Join(tempDir, "target.txt")
	if err := os.WriteFile(targetFile, []byte("target"), 0644); err != nil {
		t.Fatalf("Failed to create target file: %v", err)
	}
	symlink := filepath.Join(tempDir, "link")
	if err := os.Symlink(targetFile, symlink); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	// Create hidden file
	hiddenFile := filepath.Join(tempDir, ".secret")
	if err := os.WriteFile(hiddenFile, []byte("secret"), 0644); err != nil {
		t.Fatalf("Failed to create hidden file: %v", err)
	}

	// Create allowed hidden file
	allowedHidden := filepath.Join(tempDir, ".nojekyll")
	if err := os.WriteFile(allowedHidden, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create .nojekyll: %v", err)
	}

	// Create .git directory
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.Mkdir(gitDir, 0755); err != nil {
		t.Fatalf("Failed to create .git dir: %v", err)
	}
	gitFile := filepath.Join(gitDir, "config")
	if err := os.WriteFile(gitFile, []byte("config"), 0644); err != nil {
		t.Fatalf("Failed to create git file: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"regular file", regularFile, false},
		{"symlink", symlink, true},
		{"hidden file", hiddenFile, true},
		{"allowed hidden file", allowedHidden, false},
		{"git directory", gitDir, true},
		{"git file", gitFile, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := os.Lstat(tt.path) // Use Lstat to detect symlinks
			if err != nil {
				t.Fatalf("Failed to lstat %s: %v", tt.path, err)
			}

			result := ShouldRejectFile(tt.path, info)
			if result != tt.expected {
				t.Errorf("ShouldRejectFile(%s) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}