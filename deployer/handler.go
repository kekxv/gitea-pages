package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
)

const deletedGitReference = "0000000000000000000000000000000000000000"

// DeploymentExecutor is the deployment boundary used by the webhook handler.
// It receives only canonical repository metadata and validated targets.
type DeploymentExecutor interface {
	Deploy(context.Context, VerifiedRepository, SiteTarget) error
	Remove(context.Context, SiteTarget) error
}

// Deployer handles authenticated webhook requests and deployment.
type Deployer struct {
	config             *Config
	hookStore          HookStore
	repositoryVerifier RepositoryVerifier
	deployments        DeploymentExecutor
}

// NewWebhookDeployer constructs the post-migration webhook handler. Its
// dependencies are deliberately injected after secure storage is initialized.
func NewWebhookDeployer(config *Config, hookStore HookStore, verifier RepositoryVerifier, deployments DeploymentExecutor) *Deployer {
	return &Deployer{
		config:             config,
		hookStore:          hookStore,
		repositoryVerifier: verifier,
		deployments:        deployments,
	}
}

// HandleWebhook accepts only per-hook authenticated deliveries. The payload
// is never used to select either a credential or a clone URL.
func (d *Deployer) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if d == nil || d.config == nil || d.hookStore == nil || d.repositoryVerifier == nil || d.deployments == nil {
		log.Printf("Webhook handler is not configured")
		http.Error(w, "Webhook service unavailable", http.StatusServiceUnavailable)
		return
	}

	authenticated, err := AuthenticateWebhook(r.Context(), r, d.hookStore)
	if err != nil {
		writeWebhookError(w, err)
		return
	}
	payload, err := DecodeWebhook(authenticated.Body, r.Header.Get("X-Gitea-Event"))
	if err != nil {
		writeWebhookError(w, err)
		return
	}
	repository, err := d.repositoryVerifier.Verify(r.Context(), authenticated.Principal, payload.Repository)
	if err != nil {
		writeWebhookError(w, err)
		return
	}
	target, err := NewSiteTarget(d.config.PagesDir, repository.Owner, repository.Name, d.config.Domain)
	if err != nil {
		writeWebhookError(w, err)
		return
	}

	if !IsGhPagesBranch(payload.Ref) && !(payload.Kind == "delete" && payload.Ref == "gh-pages") {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "Ignored: not gh-pages branch")
		return
	}

	if payload.Kind == "delete" {
		if payload.RefType != "branch" {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, "Ignored: not a branch")
			return
		}
		err = d.deployments.Remove(r.Context(), target)
	} else if payload.After == deletedGitReference {
		err = d.deployments.Remove(r.Context(), target)
	} else {
		err = d.deployments.Deploy(r.Context(), *repository, target)
	}
	if err != nil {
		writeWebhookError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	if payload.Kind == "delete" || payload.After == deletedGitReference {
		_, _ = fmt.Fprintln(w, "Site removed successfully")
		return
	}
	_, _ = fmt.Fprintln(w, "Deployed successfully")
}

func writeWebhookError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPayloadTooLarge):
		http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
	case errors.Is(err, ErrInvalidAuthorization), errors.Is(err, ErrMissingDeliveryID),
		errors.Is(err, ErrMissingSignature), errors.Is(err, ErrUnknownHook),
		errors.Is(err, ErrInvalidSignature), errors.Is(err, ErrReplay):
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	case errors.Is(err, ErrUnsupportedWebhook), errors.Is(err, ErrMalformedWebhook),
		errors.Is(err, ErrInvalidPathComponent), errors.Is(err, ErrUnsafeSiteTarget):
		http.Error(w, "Bad request", http.StatusBadRequest)
	case errors.Is(err, ErrRepositoryMismatch), errors.Is(err, ErrRepositoryOutOfScope),
		errors.Is(err, ErrUntrustedCloneURL), errors.Is(err, ErrUntrustedRepositoryAPI), errors.Is(err, ErrRepositoryAccess):
		http.Error(w, "Repository forbidden", http.StatusForbidden)
	case errors.Is(err, ErrRepositoryTooLarge):
		http.Error(w, "Repository too large", http.StatusRequestEntityTooLarge)
	case errors.Is(err, ErrDeploymentSaturated):
		w.Header().Set("Retry-After", "30")
		http.Error(w, "Deployment capacity exhausted", http.StatusTooManyRequests)
	default:
		log.Printf("Webhook handling failed: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// IsGhPagesBranch identifies the deployment branch for push events.
func IsGhPagesBranch(ref string) bool {
	return ref == "refs/heads/gh-pages"
}
