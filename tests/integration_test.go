package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Integration tests for Gitea Pages Deployer

// TestGiteaWebhookPayload represents the full Gitea webhook payload
type TestGiteaWebhookPayload struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	Repository struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		Owner    struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
			Name     string `json:"name"`
			Email    string `json:"email"`
		} `json:"owner"`
		CloneURL string `json:"clone_url"`
		HTMLURL  string `json:"html_url"`
		Private  bool   `json:"private"`
	} `json:"repository"`
	Pusher struct {
		ID       int64  `json:"id"`
		Login    string `json:"login"`
		Name     string `json:"name"`
		Email    string `json:"email"`
	} `json:"pusher"`
	Commits []struct {
		ID      string `json:"id"`
		Message string `json:"message"`
	} `json:"commits"`
}

// computeTestSignature computes HMAC-SHA256 signature
func computeTestSignature(body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

// TestFullDeployFlow tests the complete deployment workflow
func TestFullDeployFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create temp pages directory
	tempPagesDir := t.TempDir()

	config := &Config{
		Domain:        "example.com",
		WebhookSecret: "test-secret",
		PagesDir:      tempPagesDir,
		MaxSiteSizeMB: 100,
	}

	deployer := NewDeployer(config)

	// Create mock git repository
	mockRepoDir := t.TempDir()
	mockRepoURL := createMockGhPagesRepo(t, mockRepoDir, "test-content")

	// Create payload
	payload := TestGiteaWebhookPayload{
		Ref: "refs/heads/gh-pages",
		Repository: struct {
			ID       int64  `json:"id"`
			Name     string `json:"name"`
			FullName string `json:"full_name"`
			Owner    struct {
				ID       int64  `json:"id"`
				Username string `json:"username"`
				Name     string `json:"name"`
				Email    string `json:"email"`
			} `json:"owner"`
			CloneURL string `json:"clone_url"`
			HTMLURL  string `json:"html_url"`
			Private  bool   `json:"private"`
		}{
			Name:     "test-repo",
			CloneURL: mockRepoURL,
			Owner: struct {
				ID       int64  `json:"id"`
				Username string `json:"username"`
				Name     string `json:"name"`
				Email    string `json:"email"`
			}{
				Username: "testuser",
			},
		},
	}

	body, _ := json.Marshal(payload)
	signature := computeTestSignature(string(body), "test-secret")

	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Gitea-Signature", signature)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	deployer.HandleWebhook(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Verify deployment
	targetDir := filepath.Join(tempPagesDir, "testuser", "test-repo")
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		t.Errorf("Target directory should exist: %s", targetDir)
	}

	// Verify .git directory is removed
	gitDir := filepath.Join(targetDir, ".git")
	if _, err := os.Stat(gitDir); !os.IsNotExist(err) {
		t.Errorf(".git directory should be removed")
	}

	// Verify content
	contentFile := filepath.Join(targetDir, "index.html")
	if _, err := os.Stat(contentFile); os.IsNotExist(err) {
		t.Errorf("index.html should exist")
	}
}

// TestRootSiteDeployment tests deployment to root site (_root directory)
func TestRootSiteDeployment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempPagesDir := t.TempDir()

	config := &Config{
		Domain:        "example.com",
		WebhookSecret: "test-secret",
		PagesDir:      tempPagesDir,
		MaxSiteSizeMB: 100,
	}

	deployer := NewDeployer(config)

	mockRepoDir := t.TempDir()
	mockRepoURL := createMockGhPagesRepo(t, mockRepoDir, "root-site-content")

	// Test with repo name matching username
	payload := TestGiteaWebhookPayload{
		Ref: "refs/heads/gh-pages",
		Repository: struct {
			ID       int64  `json:"id"`
			Name     string `json:"name"`
			FullName string `json:"full_name"`
			Owner    struct {
				ID       int64  `json:"id"`
				Username string `json:"username"`
				Name     string `json:"name"`
				Email    string `json:"email"`
			} `json:"owner"`
			CloneURL string `json:"clone_url"`
			HTMLURL  string `json:"html_url"`
			Private  bool   `json:"private"`
		}{
			Name:     "alice",
			CloneURL: mockRepoURL,
			Owner: struct {
				ID       int64  `json:"id"`
				Username string `json:"username"`
				Name     string `json:"name"`
				Email    string `json:"email"`
			}{
				Username: "alice",
			},
		},
	}

	body, _ := json.Marshal(payload)
	signature := computeTestSignature(string(body), "test-secret")

	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Gitea-Signature", signature)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	deployer.HandleWebhook(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify deployment to _root
	targetDir := filepath.Join(tempPagesDir, "alice", "_root")
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		t.Errorf("Root site directory should exist: %s", targetDir)
	}
}

// TestUnauthorizedAccess tests rejection of unauthorized webhook requests
func TestUnauthorizedAccess(t *testing.T) {
	config := &Config{
		Domain:        "example.com",
		WebhookSecret: "test-secret",
		PagesDir:      "/tmp/test-pages",
		MaxSiteSizeMB: 100,
	}

	deployer := NewDeployer(config)

	payload := TestGiteaWebhookPayload{
		Ref: "refs/heads/gh-pages",
		Repository: struct {
			ID       int64  `json:"id"`
			Name     string `json:"name"`
			FullName string `json:"full_name"`
			Owner    struct {
				ID       int64  `json:"id"`
				Username string `json:"username"`
				Name     string `json:"name"`
				Email    string `json:"email"`
			} `json:"owner"`
			CloneURL string `json:"clone_url"`
			HTMLURL  string `json:"html_url"`
			Private  bool   `json:"private"`
		}{
			Name: "test-repo",
		},
	}

	body, _ := json.Marshal(payload)

	// Test without signature
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	deployer.HandleWebhook(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d without signature, got %d", http.StatusUnauthorized, w.Code)
	}

	// Test with wrong signature
	req2 := httptest.NewRequest("POST", "/webhook", strings.NewReader(string(body)))
	req2.Header.Set("X-Gitea-Signature", "wrong-signature")
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	deployer.HandleWebhook(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d with wrong signature, got %d", http.StatusUnauthorized, w2.Code)
	}
}

// TestInvalidPayload tests handling of malformed payloads
func TestInvalidPayload(t *testing.T) {
	config := &Config{
		Domain:        "example.com",
		WebhookSecret: "test-secret",
		PagesDir:      "/tmp/test-pages",
		MaxSiteSizeMB: 100,
	}

	deployer := NewDeployer(config)

	// Test invalid JSON
	body := "invalid-json-content"
	signature := computeTestSignature(body, "test-secret")

	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
	req.Header.Set("X-Gitea-Signature", signature)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	deployer.HandleWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for invalid JSON, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestSymlinkBlockedInDeployment tests that symlinks are rejected during deployment
func TestSymlinkBlockedInDeployment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempPagesDir := t.TempDir()

	config := &Config{
		Domain:        "example.com",
		WebhookSecret: "test-secret",
		PagesDir:      tempPagesDir,
		MaxSiteSizeMB: 100,
	}

	deployer := NewDeployer(config)

	mockRepoDir := t.TempDir()
	mockRepoURL := createMockGhPagesRepoWithSymlink(t, mockRepoDir)

	payload := TestGiteaWebhookPayload{
		Ref: "refs/heads/gh-pages",
		Repository: struct {
			ID       int64  `json:"id"`
			Name     string `json:"name"`
			FullName string `json:"full_name"`
			Owner    struct {
				ID       int64  `json:"id"`
				Username string `json:"username"`
				Name     string `json:"name"`
				Email    string `json:"email"`
			} `json:"owner"`
			CloneURL string `json:"clone_url"`
			HTMLURL  string `json:"html_url"`
			Private  bool   `json:"private"`
		}{
			Name:     "symlink-repo",
			CloneURL: mockRepoURL,
			Owner: struct {
				ID       int64  `json:"id"`
				Username string `json:"username"`
				Name     string `json:"name"`
				Email    string `json:"email"`
			}{
				Username: "testuser",
			},
		},
	}

	body, _ := json.Marshal(payload)
	signature := computeTestSignature(string(body), "test-secret")

	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Gitea-Signature", signature)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	deployer.HandleWebhook(w, req)

	// Deployment should succeed but symlinks should be skipped
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify symlink is not deployed
	targetDir := filepath.Join(tempPagesDir, "testuser", "symlink-repo")
	symlinkPath := filepath.Join(targetDir, "link")
	if _, err := os.Stat(symlinkPath); !os.IsNotExist(err) {
		t.Errorf("Symlink should not be deployed")
	}
}

// Helper function to create a mock git repository with gh-pages branch
func createMockGhPagesRepo(t *testing.T, dir, content string) string {
	t.Helper()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	// Create gh-pages branch
	cmd = exec.Command("git", "checkout", "-b", "gh-pages")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create gh-pages branch: %v", err)
	}

	// Create content file
	indexFile := filepath.Join(dir, "index.html")
	contentBytes := fmt.Sprintf("<html><body>%s</body></html>", content)
	if err := os.WriteFile(indexFile, []byte(contentBytes), 0644); err != nil {
		t.Fatalf("Failed to create index.html: %v", err)
	}

	// Commit
	cmd = exec.Command("git", "add", "index.html")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "Initial commit")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	return dir
}

// Helper function to create a mock repo with symlink
func createMockGhPagesRepoWithSymlink(t *testing.T, dir string) string {
	t.Helper()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	// Create gh-pages branch
	cmd = exec.Command("git", "checkout", "-b", "gh-pages")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create gh-pages branch: %v", err)
	}

	// Create content file
	indexFile := filepath.Join(dir, "index.html")
	if err := os.WriteFile(indexFile, []byte("<html><body>test</body></html>"), 0644); err != nil {
		t.Fatalf("Failed to create index.html: %v", err)
	}

	// Create symlink
	linkPath := filepath.Join(dir, "link")
	if err := os.Symlink("/etc/passwd", linkPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	// Commit files
	cmd = exec.Command("git", "add", "-A")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "Initial commit with symlink")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	return dir
}

// TestConcurrentDeploys tests handling of concurrent deployment requests
func TestConcurrentDeploys(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempPagesDir := t.TempDir()

	config := &Config{
		Domain:        "example.com",
		WebhookSecret: "test-secret",
		PagesDir:      tempPagesDir,
		MaxSiteSizeMB: 100,
	}

	deployer := NewDeployer(config)

	// Create multiple mock repos
	numConcurrent := 3
	var mockRepoURLs []string
	for i := 0; i < numConcurrent; i++ {
		mockRepoDir := t.TempDir()
		mockRepoURL := createMockGhPagesRepo(t, mockRepoDir, fmt.Sprintf("content-%d", i))
		mockRepoURLs = append(mockRepoURLs, mockRepoURL)
	}

	// Send concurrent requests
	done := make(chan bool, numConcurrent)
	for i := 0; i < numConcurrent; i++ {
		go func(idx int) {
			payload := TestGiteaWebhookPayload{
				Ref: "refs/heads/gh-pages",
				Repository: struct {
					ID       int64  `json:"id"`
					Name     string `json:"name"`
					FullName string `json:"full_name"`
					Owner    struct {
						ID       int64  `json:"id"`
						Username string `json:"username"`
						Name     string `json:"name"`
						Email    string `json:"email"`
					} `json:"owner"`
					CloneURL string `json:"clone_url"`
					HTMLURL  string `json:"html_url"`
					Private  bool   `json:"private"`
				}{
					Name:     fmt.Sprintf("repo-%d", idx),
					CloneURL: mockRepoURLs[idx],
					Owner: struct {
						ID       int64  `json:"id"`
						Username string `json:"username"`
						Name     string `json:"name"`
						Email    string `json:"email"`
					}{
						Username: "testuser",
					},
				},
			}

			body, _ := json.Marshal(payload)
			signature := computeTestSignature(string(body), "test-secret")

			req := httptest.NewRequest("POST", "/webhook", strings.NewReader(string(body)))
			req.Header.Set("X-Gitea-Signature", signature)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			deployer.HandleWebhook(w, req)

			done <- w.Code == http.StatusOK
		}(i)
	}

	// Wait for all requests
	for i := 0; i < numConcurrent; i++ {
		select {
		case result := <-done:
			if !result {
				t.Errorf("Concurrent deployment %d failed", i)
			}
		case <-time.After(30 * time.Second):
			t.Errorf("Timeout waiting for concurrent deployment %d", i)
		}
	}

	// Verify all deployments
	for i := 0; i < numConcurrent; i++ {
		targetDir := filepath.Join(tempPagesDir, "testuser", fmt.Sprintf("repo-%d", i))
		if _, err := os.Stat(targetDir); os.IsNotExist(err) {
			t.Errorf("Target directory %s should exist", targetDir)
		}
	}
}

// TestHealthEndpoint tests the health check endpoint
func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	body, _ := io.ReadAll(w.Body)
	if strings.TrimSpace(string(body)) != "OK" {
		t.Errorf("Expected body 'OK', got '%s'", string(body))
	}
}

// TestOversizedDeployment tests rejection of oversized sites
func TestOversizedDeployment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempPagesDir := t.TempDir()

	// Set very small size limit (1MB)
	config := &Config{
		Domain:        "example.com",
		WebhookSecret: "test-secret",
		PagesDir:      tempPagesDir,
		MaxSiteSizeMB: 1, // 1MB limit
	}

	deployer := NewDeployer(config)

	mockRepoDir := t.TempDir()
	// Create a mock repo with larger content (>1MB)
	mockRepoURL := createMockGhPagesRepoWithLargeContent(t, mockRepoDir, 2*1024*1024) // 2MB

	payload := TestGiteaWebhookPayload{
		Ref: "refs/heads/gh-pages",
		Repository: struct {
			ID       int64  `json:"id"`
			Name     string `json:"name"`
			FullName string `json:"full_name"`
			Owner    struct {
				ID       int64  `json:"id"`
				Username string `json:"username"`
				Name     string `json:"name"`
				Email    string `json:"email"`
			} `json:"owner"`
			CloneURL string `json:"clone_url"`
			HTMLURL  string `json:"html_url"`
			Private  bool   `json:"private"`
		}{
			Name:     "oversized-repo",
			CloneURL: mockRepoURL,
			Owner: struct {
				ID       int64  `json:"id"`
				Username string `json:"username"`
				Name     string `json:"name"`
				Email    string `json:"email"`
			}{
				Username: "testuser",
			},
		},
	}

	body, _ := json.Marshal(payload)
	signature := computeTestSignature(string(body), "test-secret")

	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Gitea-Signature", signature)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	deployer.HandleWebhook(w, req)

	// Should fail with 500 (deployment error due to size)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d for oversized deployment, got %d", http.StatusInternalServerError, w.Code)
	}

	// Verify error message contains size limit info
	if !strings.Contains(w.Body.String(), "exceeds maximum") {
		t.Errorf("Expected error message to mention size limit, got: %s", w.Body.String())
	}

	// Verify nothing was deployed
	targetDir := filepath.Join(tempPagesDir, "testuser", "oversized-repo")
	if _, err := os.Stat(targetDir); !os.IsNotExist(err) {
		t.Errorf("Target directory should NOT exist for oversized deployment")
	}
}

// Helper function to create a mock repo with large content
func createMockGhPagesRepoWithLargeContent(t *testing.T, dir string, sizeBytes int) string {
	t.Helper()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	// Create gh-pages branch
	cmd = exec.Command("git", "checkout", "-b", "gh-pages")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create gh-pages branch: %v", err)
	}

	// Create large file
	largeFile := filepath.Join(dir, "large.bin")
	largeContent := make([]byte, sizeBytes)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}
	if err := os.WriteFile(largeFile, largeContent, 0644); err != nil {
		t.Fatalf("Failed to create large file: %v", err)
	}

	// Commit
	cmd = exec.Command("git", "add", "large.bin")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}

	cmd = exec.Command("git", "commit", "-m", "Large content")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	return dir
}