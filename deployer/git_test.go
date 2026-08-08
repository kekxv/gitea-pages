package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveGitDir(t *testing.T) {
	// Create temp directory with .git folder
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")

	// Test: .git doesn't exist
	err := RemoveGitDir(gitDir)
	if err != nil {
		t.Errorf("RemoveGitDir on non-existent dir should succeed: %v", err)
	}

	// Create .git directory
	if err := os.Mkdir(gitDir, 0755); err != nil {
		t.Fatalf("Failed to create .git dir: %v", err)
	}

	// Add some files inside .git
	testFile := filepath.Join(gitDir, "config")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test: remove existing .git
	err = RemoveGitDir(gitDir)
	if err != nil {
		t.Errorf("RemoveGitDir failed: %v", err)
	}

	// Verify .git is removed
	if _, err := os.Stat(gitDir); !os.IsNotExist(err) {
		t.Errorf(".git directory should be removed")
	}
}

func TestNewGitOperations(t *testing.T) {
	config := &Config{
		PagesDir:      "/var/www/pages",
		MaxSiteSizeMB: 100,
	}
	gitOps := NewGitOperations(config)

	if gitOps.pagesDir != "/var/www/pages" {
		t.Errorf("Expected pagesDir /var/www/pages, got %s", gitOps.pagesDir)
	}
	if gitOps.maxSiteSizeMB != 100 {
		t.Errorf("Expected maxSiteSizeMB 100, got %d", gitOps.maxSiteSizeMB)
	}
}

func TestIsAllowedHiddenFile(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{".htaccess", true},
		{".well-known", true},
		{".nojekyll", true},
		{".gitignore", true},
		{".git", false},
		{".env", false},
		{".secret", false},
		{".bashrc", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAllowedHiddenFile(tt.name)
			if result != tt.expected {
				t.Errorf("isAllowedHiddenFile(%s) = %v, expected %v", tt.name, result, tt.expected)
			}
		})
	}
}

func TestCalculateDirSize(t *testing.T) {
	// Create temp directory with known files
	tempDir := t.TempDir()

	// Create files with known sizes
	file1 := filepath.Join(tempDir, "file1.txt")
	file2 := filepath.Join(tempDir, "file2.txt")
	subDir := filepath.Join(tempDir, "subdir")
	file3 := filepath.Join(subDir, "file3.txt")

	// Create files
	os.WriteFile(file1, []byte("12345"), 0644) // 5 bytes
	os.WriteFile(file2, []byte("789"), 0644)   // 3 bytes
	os.Mkdir(subDir, 0755)
	os.WriteFile(file3, []byte("abcdef"), 0644) // 6 bytes

	// Calculate size
	size, err := CalculateDirSize(tempDir)
	if err != nil {
		t.Errorf("CalculateDirSize failed: %v", err)
	}

	expectedSize := int64(5 + 3 + 6) // 14 bytes
	if size != expectedSize {
		t.Errorf("Expected size %d, got %d", expectedSize, size)
	}
}

func TestCalculateDirSizeWithSymlink(t *testing.T) {
	tempDir := t.TempDir()

	// Create regular file
	file := filepath.Join(tempDir, "regular.txt")
	os.WriteFile(file, []byte("content"), 0644)

	// Create symlink (should be skipped in size calculation)
	symlink := filepath.Join(tempDir, "link")
	os.Symlink(file, symlink)

	size, err := CalculateDirSize(tempDir)
	if err != nil {
		t.Errorf("CalculateDirSize failed: %v", err)
	}

	// Should only count the regular file (7 bytes)
	if size != 7 {
		t.Errorf("Expected size 7 (symlink skipped), got %d", size)
	}
}
