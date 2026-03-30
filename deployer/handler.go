package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// GiteaWebhookPayload represents Gitea webhook push payload
type GiteaWebhookPayload struct {
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

// GiteaDeletePayload represents Gitea webhook branch/tag delete payload
type GiteaDeletePayload struct {
	Ref        string `json:"ref"`
	RefType    string `json:"ref_type"` // "branch" or "tag"
	Repository struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		Owner    struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
		} `json:"owner"`
	} `json:"repository"`
	Sender struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	} `json:"sender"`
}

// Deployer handles webhook requests and deployment
type Deployer struct {
	config     *Config
	gitOps     *GitOperations
	tokenStore *TokenStore // For OAuth user tokens
}

// NewDeployer creates a new Deployer instance
func NewDeployer(config *Config) *Deployer {
	return &Deployer{
		config: config,
		gitOps: NewGitOperations(config),
	}
}

// SetTokenStore sets the token store for OAuth user tokens
func (d *Deployer) SetTokenStore(store *TokenStore) {
	d.tokenStore = store
}

// HandleWebhook processes Gitea push and delete webhooks
func (d *Deployer) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body
	body, err := readBody(r)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Verify signature if secret is configured
	if d.config.WebhookSecret != "" {
		signature := r.Header.Get("X-Gitea-Signature")
		if !VerifySignature(body, signature, d.config.WebhookSecret) {
			log.Printf("Invalid signature from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Get event type from header
	eventType := r.Header.Get("X-Gitea-Event")

	// Handle delete event
	if eventType == "delete" {
		d.HandleDelete(w, r, body)
		return
	}

	// Parse push payload
	var payload GiteaWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("Error parsing payload: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Log request info
	log.Printf("Received webhook: repo=%s, ref=%s, pusher=%s",
		payload.Repository.Name, payload.Ref, payload.Pusher.Login)

	// Security: Validate clone URL to prevent token phishing
	if !IsTrustedCloneURL(payload.Repository.CloneURL, d.config.GiteaAPIURL) {
		log.Printf("Rejected untrusted clone URL: %s", payload.Repository.CloneURL)
		http.Error(w, "Untrusted clone URL", http.StatusForbidden)
		return
	}

	// Filter branch - only process gh-pages
	if !IsGhPagesBranch(payload.Ref) {
		log.Printf("Ignoring non-gh-pages branch: %s", payload.Ref)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Ignored: not gh-pages branch\n")
		return
	}

	// Check if this is a branch deletion (After is all zeros)
	if payload.After == "0000000000000000000000000000000000000000" {
		log.Printf("Branch deletion detected for %s", payload.Ref)
		d.handleBranchDelete(payload.Repository.Owner.Username, payload.Repository.Name)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Site removed successfully\n")
		return
	}

	// Calculate target path
	targetPath := CalculateTargetPath(
		d.config.PagesDir,
		payload.Repository.Owner.Username,
		payload.Repository.Name,
		d.config.Domain,
	)

	log.Printf("Deploying to: %s", targetPath)

	// Get user token for clone authentication (if OAuth is enabled)
	// Try to use OAuth token even for public repos, as Gitea may require auth for all clones
	userToken := ""
	if d.tokenStore != nil {
		userToken = d.tokenStore.GetTokenForRepo(payload.Repository.Owner.Username)
		if userToken != "" {
			log.Printf("Using OAuth token for user: %s", payload.Repository.Owner.Username)
		} else if payload.Repository.Private {
			log.Printf("Warning: Private repo but no OAuth token for user: %s", payload.Repository.Owner.Username)
		}
	}

	// Perform deployment with pre-clone size check and private repo auth
	if err := d.gitOps.DeployWithToken(payload.Repository.CloneURL, targetPath,
		payload.Repository.Owner.Username, payload.Repository.Name, userToken); err != nil {
		log.Printf("Deployment failed: %v", err)
		http.Error(w, fmt.Sprintf("Deployment failed: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully deployed %s to %s", payload.Repository.Name, targetPath)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Deployed successfully to %s\n", targetPath)
}

// HandleDelete processes Gitea delete webhook (branch/tag deletion)
func (d *Deployer) HandleDelete(w http.ResponseWriter, r *http.Request, body []byte) {
	var payload GiteaDeletePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("Error parsing delete payload: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	log.Printf("Received delete webhook: ref=%s, ref_type=%s, repo=%s, sender=%s",
		payload.Ref, payload.RefType, payload.Repository.FullName, payload.Sender.Login)

	// Only process branch deletions
	if payload.RefType != "branch" {
		log.Printf("Ignoring non-branch deletion: %s", payload.RefType)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Ignored: not a branch\n")
		return
	}

	// Only process gh-pages branch deletions
	if payload.Ref != "gh-pages" {
		log.Printf("Ignoring non-gh-pages branch deletion: %s", payload.Ref)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Ignored: not gh-pages branch\n")
		return
	}

	// Delete the site
	d.handleBranchDelete(payload.Repository.Owner.Username, payload.Repository.Name)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Site removed successfully\n")
}

// handleBranchDelete removes the deployed site
func (d *Deployer) handleBranchDelete(username, repoName string) {
	targetPath := CalculateTargetPath(
		d.config.PagesDir,
		username,
		repoName,
		d.config.Domain,
	)

	log.Printf("Removing site at: %s", targetPath)

	if err := d.gitOps.RemoveSite(targetPath); err != nil {
		log.Printf("Failed to remove site: %v", err)
	} else {
		log.Printf("Successfully removed site for %s/%s", username, repoName)
	}
}

// VerifySignature validates HMAC-SHA256 signature from Gitea
func VerifySignature(body []byte, signature, secret string) bool {
	if signature == "" {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

// IsGhPagesBranch checks if ref is gh-pages branch
func IsGhPagesBranch(ref string) bool {
	return ref == "refs/heads/gh-pages"
}

// CalculateTargetPath determines where to deploy files
// Root site: repoName starts with "username.pages." (GitHub-style: username.github.io)
//   -> /pagesDir/username/_root
// Sub site: other repos -> /pagesDir/username/repoName
func CalculateTargetPath(pagesDir, username, repoName, domain string) string {
	sUsername := SanitizePathComponent(username)
	sRepoName := SanitizePathComponent(repoName)

	// Check if this is a root site (GitHub-style: username.github.io)
	// Format: username.pages.<anything> or username.pages.<domain>
	pagesPrefix := fmt.Sprintf("%s.pages.", username)
	isRootSite := strings.HasPrefix(repoName, pagesPrefix)

	if isRootSite {
		return fmt.Sprintf("%s/%s/_root", pagesDir, sUsername)
	}

	return fmt.Sprintf("%s/%s/%s", pagesDir, sUsername, sRepoName)
}

// readBody reads request body safely with size limit
func readBody(r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20) // 1MB max
	return readAll(r.Body)
}

func readAll(r io.ReadCloser) ([]byte, error) {
	defer r.Close()
	return io.ReadAll(r)
}