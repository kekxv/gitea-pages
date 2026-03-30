package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPrepareCloneURL(t *testing.T) {
	tests := []struct {
		name        string
		cloneURL    string
		accessToken string
		sshKeyPath  string
		expected    string
	}{
		{
			name:        "no auth - original URL",
			cloneURL:    "https://gitea.example.com/owner/repo.git",
			accessToken: "",
			sshKeyPath:  "",
			expected:    "https://gitea.example.com/owner/repo.git",
		},
		{
			name:        "SSH key configured - convert to SSH URL",
			cloneURL:    "https://gitea.example.com/owner/repo.git",
			accessToken: "",
			sshKeyPath:  "/path/to/key",
			expected:    "git@gitea.example.com:owner/repo.git",
		},
		{
			name:        "access token - inject into HTTPS URL",
			cloneURL:    "https://gitea.example.com/owner/repo.git",
			accessToken: "my-token",
			sshKeyPath:  "",
			expected:    "https://my-token@gitea.example.com/owner/repo.git",
		},
		{
			name:        "SSH takes precedence over token",
			cloneURL:    "https://gitea.example.com/owner/repo.git",
			accessToken: "my-token",
			sshKeyPath:  "/path/to/key",
			expected:    "git@gitea.example.com:owner/repo.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := PrepareCloneURL(tt.cloneURL, tt.accessToken, tt.sshKeyPath)
			if err != nil {
				t.Errorf("PrepareCloneURL failed: %v", err)
			}
			if result != tt.expected {
				t.Errorf("PrepareCloneURL() = %s, expected %s", result, tt.expected)
			}
		})
	}
}

func TestIsTrustedCloneURL(t *testing.T) {
	trustedAPI := "https://gitea.example.com/api/v1"
	tests := []struct {
		name     string
		cloneURL string
		expected bool
	}{
		{"trusted", "https://gitea.example.com/user/repo.git", true},
		{"untrusted", "https://attacker.com/user/repo.git", false},
		{"subdomain (untrusted by default)", "https://sub.gitea.example.com/user/repo.git", false},
		{"internal", "http://localhost:3000/user/repo.git", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTrustedCloneURL(tt.cloneURL, trustedAPI); got != tt.expected {
				t.Errorf("IsTrustedCloneURL() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestGiteaClient_GetRepoInfo(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/repos/testuser/test-repo" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": 1,
			"name": "test-repo",
			"full_name": "testuser/test-repo",
			"size": 5000,
			"private": true,
			"owner": {"id": 1, "username": "testuser"}
		}`))
	}))
	defer mockServer.Close()

	client := NewGiteaClient(mockServer.URL, "test-token")
	repoInfo, err := client.GetRepoInfo("testuser", "test-repo")
	if err != nil {
		t.Errorf("GetRepoInfo failed: %v", err)
	}

	if repoInfo == nil {
		t.Error("Expected repoInfo to be returned")
		return
	}

	if repoInfo.Name != "test-repo" {
		t.Errorf("Expected name test-repo, got %s", repoInfo.Name)
	}

	if repoInfo.Size != 5000 {
		t.Errorf("Expected size 5000 KB, got %d", repoInfo.Size)
	}
}

func TestGiteaClient_CheckRepoSizeBeforeClone(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": 1,
			"name": "test-repo",
			"full_name": "testuser/test-repo",
			"size": 200000,
			"owner": {"id": 1, "username": "testuser"}
		}`))
	}))
	defer mockServer.Close()

	client := NewGiteaClient(mockServer.URL, "test-token")

	maxSizeBytes := int64(50 * 1024 * 1024) // 50MB
	err := client.CheckRepoSizeBeforeClone("testuser", "test-repo", maxSizeBytes)
	if err == nil {
		t.Error("Expected error for oversized repo")
	}
}

func TestGiteaClient_NotConfigured(t *testing.T) {
	client := NewGiteaClient("", "")
	repoInfo, err := client.GetRepoInfo("testuser", "test-repo")
	if err != nil {
		t.Errorf("Should not error when API not configured: %v", err)
	}
	if repoInfo != nil {
		t.Error("Should return nil when API not configured")
	}
}

func TestSetupSSHKey_NotExists(t *testing.T) {
	err := SetupSSHKey("/nonexistent/path/key")
	if err == nil {
		t.Error("Expected error for non-existent SSH key")
	}
}

func TestSetupSSHKey_EmptyPath(t *testing.T) {
	err := SetupSSHKey("")
	if err != nil {
		t.Errorf("SetupSSHKey with empty path should succeed: %v", err)
	}
}