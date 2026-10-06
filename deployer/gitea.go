package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const deploymentStatusContext = "continuous-integration/gitea-pages"

// CreateCommitStatus publishes the result of a deployment for one commit.
// Gitea accepts the same success state used by its CI integrations.
func (c *GiteaClient) CreateCommitStatus(ctx context.Context, owner, repo, sha, targetURL string) error {
	if c == nil || c.apiURL == "" || c.accessToken == "" || owner == "" || repo == "" || sha == "" {
		return fmt.Errorf("commit status client is not configured")
	}
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/statuses/%s", c.apiURL, url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(sha))
	payload, err := json.Marshal(map[string]string{
		"state":       "success",
		"context":     deploymentStatusContext,
		"description": "Gitea Pages deployment succeeded",
		"target_url":  targetURL,
	})
	if err != nil {
		return fmt.Errorf("encode commit status: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create commit status request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := noRedirectHTTPClient(nil, 10*time.Second, ErrUntrustedRepositoryAPI).Do(req)
	if err != nil {
		return fmt.Errorf("commit status request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &GiteaAPIError{StatusCode: resp.StatusCode, Message: string(body)}
	}
	return nil
}

type GiteaAPIError struct {
	StatusCode int
	Message    string
}

func (e *GiteaAPIError) Error() string {
	return fmt.Sprintf("Gitea API returned status %d: %s", e.StatusCode, e.Message)
}

// GiteaClient handles Gitea API operations
type GiteaClient struct {
	apiURL      string
	accessToken string
}

type giteaCommitStatusReporter struct{ apiURL string }

func (r *giteaCommitStatusReporter) ReportDeploymentSuccess(ctx context.Context, repo VerifiedRepository, sha string) error {
	if r == nil {
		return fmt.Errorf("commit status reporter is not configured")
	}
	return NewGiteaClient(r.apiURL, repo.AccessToken).CreateCommitStatus(ctx, repo.Owner, repo.Name, sha, "")
}

func NewGiteaCommitStatusReporter(apiURL string) CommitStatusReporter {
	return &giteaCommitStatusReporter{apiURL: strings.TrimSuffix(apiURL, "/")}
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var message struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &message)
		return nil, &GiteaAPIError{StatusCode: resp.StatusCode, Message: message.Message}
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
