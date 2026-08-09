package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	ErrRepositoryMismatch     = errors.New("webhook repository does not match canonical repository")
	ErrRepositoryOutOfScope   = errors.New("canonical repository is outside hook scope")
	ErrUntrustedCloneURL      = errors.New("canonical repository clone URL is untrusted")
	ErrUntrustedRepositoryAPI = errors.New("canonical repository API response is untrusted")
	ErrRepositoryAccess       = errors.New("no access token for webhook principal")
	ErrUnsupportedWebhook     = errors.New("unsupported webhook event")
	ErrMalformedWebhook       = errors.New("malformed webhook payload")
)

// VerifiedRepository is canonical repository metadata fetched from Gitea.
// It deliberately contains no clone or privacy values supplied by the webhook.
type VerifiedRepository struct {
	ID          int64
	Owner       string
	Name        string
	CloneURL    *url.URL
	Private     bool
	SizeBytes   int64
	AccessToken string
}

// PayloadRepository is the small, untrusted repository reference decoded from
// a webhook. It is used only to locate and cross-check canonical metadata.
type PayloadRepository struct {
	ID            int64
	Name          string
	OwnerUsername string
}

// WebhookEvent is the safe subset of a supported Gitea webhook event.
type WebhookEvent struct {
	Kind       string
	Ref        string
	After      string
	RefType    string
	Repository PayloadRepository
}

type RepositoryVerifier interface {
	Verify(ctx context.Context, principal HookPrincipal, payload PayloadRepository) (*VerifiedRepository, error)
}

// GiteaRepositoryVerifier resolves untrusted webhook repository references
// through the configured Gitea API using only the authenticated principal's
// OAuth token.
type GiteaRepositoryVerifier struct {
	apiBase    *url.URL
	tokenStore *TokenStore
}

func NewRepositoryVerifier(apiURL string, tokenStore *TokenStore) (*GiteaRepositoryVerifier, error) {
	apiBase, err := parseHTTPURL(apiURL)
	if err != nil {
		return nil, fmt.Errorf("parse Gitea API URL: %w", err)
	}
	if apiBase.User != nil {
		return nil, errors.New("Gitea API URL must not include credentials")
	}
	if tokenStore == nil {
		return nil, errors.New("token store is required")
	}
	return &GiteaRepositoryVerifier{apiBase: apiBase, tokenStore: tokenStore}, nil
}

func (v *GiteaRepositoryVerifier) Verify(ctx context.Context, principal HookPrincipal, payload PayloadRepository) (*VerifiedRepository, error) {
	if v == nil || v.tokenStore == nil || v.apiBase == nil {
		return nil, ErrRepositoryAccess
	}
	if principal.Username == "" {
		return nil, ErrRepositoryAccess
	}
	token := v.tokenStore.Get(principal.Username)
	if token == nil || token.AccessToken == "" {
		return nil, ErrRepositoryAccess
	}

	client := NewGiteaClient(v.apiBase.String(), token.AccessToken)
	repo, err := client.GetRepoInfoContext(ctx, payload.OwnerUsername, payload.Name)
	if err != nil {
		return nil, fmt.Errorf("fetch canonical repository: %w", err)
	}
	if repo == nil {
		return nil, fmt.Errorf("fetch canonical repository: %w", ErrRepositoryMismatch)
	}
	if repo.ID != payload.ID || repo.Owner.Username != payload.OwnerUsername || repo.Name != payload.Name {
		return nil, ErrRepositoryMismatch
	}
	if principal.ScopeType != ScopeUser && principal.ScopeType != ScopeOrganization {
		return nil, ErrRepositoryOutOfScope
	}
	if repo.Owner.Username != principal.ScopeName {
		return nil, ErrRepositoryOutOfScope
	}
	cloneURL, err := ValidateCanonicalCloneURL(repo.CloneURL, v.apiBase)
	if err != nil {
		return nil, err
	}

	return &VerifiedRepository{
		ID:          repo.ID,
		Owner:       repo.Owner.Username,
		Name:        repo.Name,
		CloneURL:    cloneURL,
		Private:     repo.Private,
		SizeBytes:   repo.Size * 1024,
		AccessToken: token.AccessToken,
	}, nil
}

// DecodeWebhook extracts only fields that are later verified against Gitea.
// Clone and privacy values from the signed but untrusted payload are omitted.
func DecodeWebhook(body []byte, eventType string) (WebhookEvent, error) {
	if eventType != "push" && eventType != "delete" {
		return WebhookEvent{}, ErrUnsupportedWebhook
	}
	var payload struct {
		Ref        string `json:"ref"`
		After      string `json:"after"`
		RefType    string `json:"ref_type"`
		Repository struct {
			ID    int64  `json:"id"`
			Name  string `json:"name"`
			Owner struct {
				Username string `json:"username"`
			} `json:"owner"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return WebhookEvent{}, fmt.Errorf("%w: %v", ErrMalformedWebhook, err)
	}
	if payload.Ref == "" || payload.Repository.ID <= 0 || payload.Repository.Name == "" || payload.Repository.Owner.Username == "" {
		return WebhookEvent{}, ErrMalformedWebhook
	}
	if eventType == "delete" && payload.RefType == "" {
		return WebhookEvent{}, ErrMalformedWebhook
	}
	return WebhookEvent{
		Kind:    eventType,
		Ref:     payload.Ref,
		After:   payload.After,
		RefType: payload.RefType,
		Repository: PayloadRepository{
			ID:            payload.Repository.ID,
			Name:          payload.Repository.Name,
			OwnerUsername: payload.Repository.Owner.Username,
		},
	}, nil
}

// ValidateCanonicalCloneURL only accepts a credential-free clone URL at the
// configured Gitea origin. HTTP is limited to the local-development API base
// condition already enforced by configuration validation.
func ValidateCanonicalCloneURL(raw string, apiBase *url.URL) (*url.URL, error) {
	if apiBase == nil {
		return nil, ErrUntrustedCloneURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" {
		return nil, ErrUntrustedCloneURL
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" || apiBase.Scheme != "http" || !isLocalDevelopmentHost(apiBase.Hostname()) {
			return nil, ErrUntrustedCloneURL
		}
	}
	if !strings.EqualFold(u.Hostname(), apiBase.Hostname()) || effectivePort(u) != effectivePort(apiBase) {
		return nil, ErrUntrustedCloneURL
	}
	if !strings.HasSuffix(u.EscapedPath(), ".git") || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrUntrustedCloneURL
	}
	return u, nil
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	if u.Scheme == "http" {
		return "80"
	}
	return ""
}
