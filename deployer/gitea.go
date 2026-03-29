package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GiteaClient handles Gitea API operations
type GiteaClient struct {
	apiURL      string
	accessToken string
}

// NewGiteaClient creates a new Gitea API client
func NewGiteaClient(apiURL, accessToken string) *GiteaClient {
	return &GiteaClient{
		apiURL:      strings.TrimSuffix(apiURL, "/"),
		accessToken: accessToken,
	}
}

// RepoInfo contains repository information from Gitea API
type RepoInfo struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Size     int64  `json:"size"` // Size in KB
	Private  bool   `json:"private"`
	Owner    struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	} `json:"owner"`
}

// GetRepoInfo fetches repository information from Gitea API
func (c *GiteaClient) GetRepoInfo(owner, repo string) (*RepoInfo, error) {
	if c.apiURL == "" || c.accessToken == "" {
		return nil, nil // API not configured, skip pre-check
	}

	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s", c.apiURL, owner, repo)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var repoInfo RepoInfo
	if err := json.Unmarshal(body, &repoInfo); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &repoInfo, nil
}

// CheckRepoSizeBeforeClone checks repository size via API before cloning
func (c *GiteaClient) CheckRepoSizeBeforeClone(owner, repo string, maxSizeBytes int64) error {
	repoInfo, err := c.GetRepoInfo(owner, repo)
	if err != nil {
		fmt.Printf("Warning: pre-clone size check failed: %v\n", err)
		return nil
	}

	if repoInfo == nil {
		return nil
	}

	repoSizeBytes := repoInfo.Size * 1024

	if repoSizeBytes > maxSizeBytes*2 {
		return fmt.Errorf("repository size %d MB exceeds safe limit (pre-clone check)", repoSizeBytes/1024/1024)
	}

	fmt.Printf("Pre-clone check: repo size %d MB\n", repoSizeBytes/1024/1024)
	return nil
}

// PrepareCloneURL prepares authenticated clone URL
func PrepareCloneURL(cloneURL string, accessToken string, sshKeyPath string) (string, error) {
	// If SSH key is configured, convert HTTPS URL to SSH
	if sshKeyPath != "" {
		if strings.HasPrefix(cloneURL, "https://") {
			parsed, err := parseURL(cloneURL)
			if err != nil {
				return "", err
			}
			sshURL := fmt.Sprintf("git@%s:%s", parsed.Host, strings.TrimPrefix(parsed.Path, "/"))
			return sshURL, nil
		}
	}

	// Use access token for HTTPS clone
	if accessToken != "" && strings.HasPrefix(cloneURL, "https://") {
		parsed, err := parseURL(cloneURL)
		if err != nil {
			return "", err
		}
		authURL := fmt.Sprintf("https://%s@%s%s", accessToken, parsed.Host, parsed.Path)
		return authURL, nil
	}

	return cloneURL, nil
}

func parseURL(rawURL string) (struct {
	Scheme string
	Host   string
	Path   string
}, error) {
	var result struct {
		Scheme string
		Host   string
		Path   string
	}

	idx := strings.Index(rawURL, "://")
	if idx == -1 {
		return result, fmt.Errorf("invalid URL: %s", rawURL)
	}

	result.Scheme = rawURL[:idx]
	rest := rawURL[idx+3:]

	slashIdx := strings.Index(rest, "/")
	if slashIdx == -1 {
		result.Host = rest
		result.Path = ""
	} else {
		result.Host = rest[:slashIdx]
		result.Path = rest[slashIdx:]
	}

	return result, nil
}

// SetupSSHKey prepares SSH key for git operations
func SetupSSHKey(sshKeyPath string) error {
	if sshKeyPath == "" {
		return nil
	}

	sshDir := filepath.Dir(sshKeyPath)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create SSH dir: %w", err)
	}

	info, err := os.Stat(sshKeyPath)
	if err != nil {
		return fmt.Errorf("SSH key not accessible: %w", err)
	}

	if info.Mode().Perm() != 0600 {
		fmt.Printf("Warning: SSH key has incorrect permissions %v, should be 0600\n", info.Mode().Perm())
	}

	return nil
}