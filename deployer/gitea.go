package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	CloneURL string `json:"clone_url"`
	Size     int64  `json:"size"` // Size in KB
	Private  bool   `json:"private"`
	Owner    struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	} `json:"owner"`
}

// GetRepoInfo fetches repository information from Gitea API
func (c *GiteaClient) GetRepoInfo(owner, repo string) (*RepoInfo, error) {
	return c.GetRepoInfoContext(context.Background(), owner, repo)
}

// GetRepoInfoContext fetches repository information from Gitea API with the
// caller's cancellation and deadline.
func (c *GiteaClient) GetRepoInfoContext(ctx context.Context, owner, repo string) (*RepoInfo, error) {
	if c.apiURL == "" || c.accessToken == "" {
		return nil, nil // API not configured, skip pre-check
	}

	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s", c.apiURL, owner, repo)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	client := noRedirectHTTPClient(nil, 10*time.Second, ErrUntrustedRepositoryAPI)
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

// IsTrustedCloneURL verifies if the clone URL belongs to the configured Gitea host
func IsTrustedCloneURL(cloneURL, trustedAPIURL string) bool {
	parsedTrusted, err := parseHTTPURL(trustedAPIURL)
	if err != nil {
		return false
	}
	_, err = ValidateCanonicalCloneURL(cloneURL, parsedTrusted)
	return err == nil
}
