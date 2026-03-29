package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// autoRegisterWebhooks automatically registers webhooks for all user repositories
func autoRegisterWebhooks(config *Config) {
	time.Sleep(5 * time.Second)

	if config.GiteaAccessToken == "" || config.GiteaAPIURL == "" {
		return
	}

	// Get user's repositories
	repos, err := getUserRepositories(config.GiteaAPIURL, config.GiteaAccessToken)
	if err != nil {
		log.Printf("Auto-register: failed to get repositories: %v", err)
		return
	}

	log.Printf("Auto-register: found %d repositories", len(repos))

	webhookURL := "http://deployer:8080/webhook"
	successCount := 0

	for _, repo := range repos {
		if err := registerWebhook(config.GiteaAPIURL, config.GiteaAccessToken, repo.FullName, webhookURL, config.WebhookSecret); err != nil {
			if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "已存在") {
				log.Printf("Auto-register: webhook already exists for %s", repo.FullName)
				successCount++
			} else {
				log.Printf("Auto-register: failed for %s: %v", repo.FullName, err)
			}
		} else {
			log.Printf("Auto-register: webhook registered for %s", repo.FullName)
			successCount++
		}
	}

	log.Printf("Auto-register: complete (%d/%d webhooks configured)", successCount, len(repos))
}

// Repository represents a Gitea repository
type Repository struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
}

// getUserRepositories fetches all repositories for the authenticated user
func getUserRepositories(apiURL, token string) ([]Repository, error) {
	url := strings.TrimSuffix(apiURL, "/") + "/api/v1/user/repos?limit=100"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read raw body first to handle both array and object responses
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Check for error response (object instead of array)
	if resp.StatusCode >= 400 {
		var errResp struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Message != "" {
			return nil, fmt.Errorf("API error: %s", errResp.Message)
		}
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var repos []Repository
	if err := json.Unmarshal(body, &repos); err != nil {
		return nil, fmt.Errorf("failed to parse repositories: %v", err)
	}

	return repos, nil
}

// registerWebhook creates a webhook for a repository
func registerWebhook(apiURL, token, repoFullName, webhookURL, secret string) error {
	url := strings.TrimSuffix(apiURL, "/") + "/api/v1/repos/" + repoFullName + "/hooks"

	payload := map[string]interface{}{
		"type": "gitea",
		"config": map[string]string{
			"url":          webhookURL,
			"content_type": "json",
			"secret":       secret,
		},
		"events": []string{"push", "delete"},
		"active": true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp struct {
			Message string `json:"message"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Message != "" {
			return fmt.Errorf("%s", errResp.Message)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return nil
}