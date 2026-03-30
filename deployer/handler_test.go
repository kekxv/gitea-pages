package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		secret    string
		signature string
		expected  bool
	}{
		{
			name:      "valid signature",
			body:      `{"ref":"refs/heads/gh-pages"}`,
			secret:    "test-secret",
			signature: computeSignature(`{"ref":"refs/heads/gh-pages"}`, "test-secret"),
			expected:  true,
		},
		{
			name:      "invalid signature",
			body:      `{"ref":"refs/heads/gh-pages"}`,
			secret:    "test-secret",
			signature: "invalid-signature",
			expected:  false,
		},
		{
			name:      "empty signature",
			body:      `{"ref":"refs/heads/gh-pages"}`,
			secret:    "test-secret",
			signature: "",
			expected:  false,
		},
		{
			name:      "wrong secret",
			body:      `{"ref":"refs/heads/gh-pages"}`,
			secret:    "test-secret",
			signature: computeSignature(`{"ref":"refs/heads/gh-pages"}`, "wrong-secret"),
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifySignature([]byte(tt.body), tt.signature, tt.secret)
			if result != tt.expected {
				t.Errorf("VerifySignature() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func computeSignature(body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestIsGhPagesBranch(t *testing.T) {
	tests := []struct {
		ref      string
		expected bool
	}{
		{"refs/heads/gh-pages", true},
		{"refs/heads/main", false},
		{"refs/heads/master", false},
		{"refs/heads/develop", false},
		{"gh-pages", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			result := IsGhPagesBranch(tt.ref)
			if result != tt.expected {
				t.Errorf("IsGhPagesBranch(%s) = %v, expected %v", tt.ref, result, tt.expected)
			}
		})
	}
}

func TestCalculateTargetPath(t *testing.T) {
	tests := []struct {
		name     string
		pagesDir string
		username string
		repoName string
		domain   string
		expected string
	}{
		{
			name:     "root site - repo is username.pages.domain",
			pagesDir: "/var/www/pages",
			username: "alice",
			repoName: "alice.pages.example.com",
			domain:   "example.com",
			expected: "/var/www/pages/alice/_root",
		},
		{
			name:     "root site - username.pages.local",
			pagesDir: "/var/www/pages",
			username: "testuser",
			repoName: "testuser.pages.local",
			domain:   "pages.local",
			expected: "/var/www/pages/testuser/_root",
		},
		{
			name:     "sub directory site",
			pagesDir: "/var/www/pages",
			username: "alice",
			repoName: "my-project",
			domain:   "example.com",
			expected: "/var/www/pages/alice/my-project",
		},
		{
			name:     "malicious username - path traversal",
			pagesDir: "/var/www/pages",
			username: "../../etc",
			repoName: "my-project",
			domain:   "example.com",
			expected: "/var/www/pages/etc/my-project",
		},
		{
			name:     "malicious repo - path traversal",
			pagesDir: "/var/www/pages",
			username: "alice",
			repoName: "../../etc/passwd",
			domain:   "example.com",
			expected: "/var/www/pages/alice/etcpasswd",
		},
		{
			name:     "uppercase username - normalized to lowercase",
			pagesDir: "/var/www/pages",
			username: "Caesar",
			repoName: "my-project",
			domain:   "example.com",
			expected: "/var/www/pages/caesar/my-project",
		},
		{
			name:     "uppercase username root site - normalized",
			pagesDir: "/var/www/pages",
			username: "Caesar",
			repoName: "Caesar.pages.example.com",
			domain:   "example.com",
			expected: "/var/www/pages/caesar/_root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateTargetPath(tt.pagesDir, tt.username, tt.repoName, tt.domain)
			if result != tt.expected {
				t.Errorf("CalculateTargetPath() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestHandleWebhook_MethodCheck(t *testing.T) {
	config := &Config{
		Domain:        "example.com",
		WebhookSecret: "test-secret",
		PagesDir:      "/tmp/test-pages",
		MaxSiteSizeMB: 100,
	}
	deployer := NewDeployer(config)

	// Test non-POST methods
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/webhook", nil)
			w := httptest.NewRecorder()
			deployer.HandleWebhook(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
			}
		})
	}
}

func TestHandleWebhook_InvalidSignature(t *testing.T) {
	config := &Config{
		Domain:        "example.com",
		WebhookSecret: "test-secret",
		PagesDir:      "/tmp/test-pages",
		MaxSiteSizeMB: 100,
	}
	deployer := NewDeployer(config)

	payload := GiteaWebhookPayload{
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
			CloneURL: "https://gitea.example.com/test/test-repo.git",
		},
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Gitea-Signature", "invalid-signature")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	deployer.HandleWebhook(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestHandleWebhook_NonGhPagesBranch(t *testing.T) {
	config := &Config{
		Domain:        "example.com",
		WebhookSecret: "test-secret",
		PagesDir:      "/tmp/test-pages",
		MaxSiteSizeMB: 100,
	}
	deployer := NewDeployer(config)

	payload := GiteaWebhookPayload{
		Ref: "refs/heads/main",
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
			CloneURL: "https://gitea.example.com/test/test-repo.git",
		},
	}

	body, _ := json.Marshal(payload)
	signature := computeSignature(string(body), "test-secret")
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Gitea-Signature", signature)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	deployer.HandleWebhook(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	if !strings.Contains(w.Body.String(), "Ignored") {
		t.Errorf("Expected 'Ignored' in response body, got: %s", w.Body.String())
	}
}