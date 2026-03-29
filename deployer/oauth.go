package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OAuthConfig holds OAuth2 configuration
type OAuthConfig struct {
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	AuthURL         string
	TokenURL        string
	APIURL          string
	PublicAuthURL   string // URL for browser redirects (may differ from AuthURL for internal API)
}

// UserToken represents a user's OAuth2 token
type UserToken struct {
	Username    string    `json:"username"`
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// TokenStore stores user tokens in memory (use database in production)
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*UserToken
}

// NewTokenStore creates a new token store
func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens: make(map[string]*UserToken),
	}
}

// Set stores a user token
func (s *TokenStore) Set(username string, token *UserToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[username] = token
}

// Get retrieves a user token
func (s *TokenStore) Get(username string) *UserToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tokens[username]
}

// GetTokenForRepo returns the access token for a repository owner
func (s *TokenStore) GetTokenForRepo(owner string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if token, ok := s.tokens[owner]; ok {
		return token.AccessToken
	}
	return ""
}

// OAuthHandler handles OAuth2 authentication
type OAuthHandler struct {
	config     *OAuthConfig
	store      *TokenStore
	webhookURL string
	secret     string
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(config *OAuthConfig, store *TokenStore, webhookURL, secret string) *OAuthHandler {
	return &OAuthHandler{
		config:     config,
		store:      store,
		webhookURL: webhookURL,
		secret:     secret,
	}
}

// generateState generates a random state string
func generateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// HandleStart starts the OAuth2 authorization flow
func (h *OAuthHandler) HandleStart(w http.ResponseWriter, r *http.Request) {
	// Show authorization confirmation page first
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>授权 Gitea Pages</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 80px auto; padding: 20px; }
        .container { background: white; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 40px; }
        h1 { color: #1f2937; margin-bottom: 8px; }
        .permissions { background: #f3f4f6; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .permission { display: flex; align-items: center; margin: 12px 0; }
        .permission-icon { width: 24px; height: 24px; background: #dbeafe; border-radius: 50%%; margin-right: 12px; display: flex; align-items: center; justify-content: center; color: #3b82f6; }
        .permission-text { flex: 1; }
        .permission-text h4 { margin: 0 0 4px 0; color: #1f2937; }
        .permission-text p { margin: 0; color: #6b7280; font-size: 14px; }
        .btn { display: inline-block; background: #3b82f6; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 500; margin-right: 12px; }
        .btn:hover { background: #2563eb; }
        .btn-cancel { background: #6b7280; }
        .btn-cancel:hover { background: #4b5563; }
        .note { color: #6b7280; font-size: 14px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 授权 Gitea Pages</h1>
        <p>Gitea Pages 需要以下权限来自动部署您的静态网站：</p>

        <div class="permissions">
            <div class="permission">
                <div class="permission-icon">👤</div>
                <div class="permission-text">
                    <h4>读取用户信息</h4>
                    <p>获取您的用户名，用于标识站点所有权</p>
                </div>
            </div>
            <div class="permission">
                <div class="permission-icon">📖</div>
                <div class="permission-text">
                    <h4>读取仓库</h4>
                    <p>克隆您的仓库代码进行部署</p>
                </div>
            </div>
            <div class="permission">
                <div class="permission-icon">🔗</div>
                <div class="permission-text">
                    <h4>管理 Webhook</h4>
                    <p>自动为您的仓库注册 Webhook，实现推送即部署</p>
                </div>
            </div>
        </div>

        <p>
            <a href="/oauth/authorize" class="btn">授权并继续</a>
            <a href="/" class="btn btn-cancel">取消</a>
        </p>

        <p class="note">💡 授权后，您可以在 Gitea 设置中随时撤销此授权</p>
    </div>
</body>
</html>`)
}

// HandleAuthorize performs the actual OAuth redirect
func (h *OAuthHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Determine redirect URL based on request Host
	host := r.Host
	redirectURL := h.config.RedirectURL

	// If request comes from a different host, construct redirect URL from request
	if host != "" && !strings.Contains(h.config.RedirectURL, host) {
		// Extract scheme (assume http for now, could check X-Forwarded-Proto)
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		redirectURL = fmt.Sprintf("%s://%s/oauth/callback", scheme, host)
	}

	// Store both state and redirect URL in cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_redirect",
		Value:    redirectURL,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
	})

	// Use PublicAuthURL for browser redirect (different from internal AuthURL)
	authURL := h.config.PublicAuthURL
	if authURL == "" {
		authURL = h.config.AuthURL // fallback
	}

	// Redirect to OAuth provider
	authRedirectURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&state=%s&scope=read:user%%20read:repository%%20write:repository",
		authURL,
		h.config.ClientID,
		redirectURL,
		state,
	)

	log.Printf("OAuth redirect URL: %s (host: %s)", authRedirectURL, host)
	http.Redirect(w, r, authRedirectURL, http.StatusTemporaryRedirect)
}

// HandleCallback handles the OAuth2 callback
func (h *OAuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("OAuth callback received: %s", r.URL.String())
	log.Printf("Query parameters: %s", r.URL.RawQuery)

	// Verify state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		log.Printf("State cookie not found: %v", err)
		http.Error(w, "State cookie not found", http.StatusBadRequest)
		return
	}

	log.Printf("State from cookie: %s, State from URL: %s", stateCookie.Value, r.URL.Query().Get("state"))

	if stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// Get the redirect URL that was used during authorization
	redirectCookie, err := r.Cookie("oauth_redirect")
	redirectURL := h.config.RedirectURL
	if err == nil && redirectCookie.Value != "" {
		redirectURL = redirectCookie.Value
	}

	code := r.URL.Query().Get("code")
	log.Printf("Authorization code: %s", code)
	if code == "" {
		http.Error(w, "No authorization code", http.StatusBadRequest)
		return
	}

	// Exchange code for token with the same redirect URL used in authorization
	token, err := h.exchangeCode(code, redirectURL)
	if err != nil {
		log.Printf("Failed to exchange token: %v", err)
		http.Error(w, "Failed to get token", http.StatusInternalServerError)
		return
	}

	// Get user info
	userInfo, err := h.getUserInfo(token.AccessToken)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Store token
	userToken := &UserToken{
		Username:    userInfo["login"].(string),
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		CreatedAt:   time.Now(),
	}
	h.store.Set(userToken.Username, userToken)

	// Register webhooks for user's repositories
	go h.registerWebhooks(userToken)

	// Show success page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>授权成功</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 80px auto; padding: 20px; text-align: center; }
        .success { color: #22c55e; font-size: 64px; }
        h1 { color: #1f2937; }
        .info { background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0; }
        a { color: #3b82f6; }
    </style>
</head>
<body>
    <div class="success">✓</div>
    <h1>授权成功！</h1>
    <div class="info">
        <p><strong>用户:</strong> %s</p>
        <p>正在自动注册 Webhook...</p>
    </div>
    <p>现在你可以推送代码到 <code>gh-pages</code> 分支来自动部署你的网站了。</p>
    <p><a href="/">返回首页</a></p>
</body>
</html>
`, userToken.Username)
}

// OAuthTokenResponse represents the token response
type OAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// exchangeCode exchanges authorization code for access token
func (h *OAuthHandler) exchangeCode(code string, redirectURL string) (*OAuthTokenResponse, error) {
	url := h.config.TokenURL

	data := fmt.Sprintf("grant_type=authorization_code&client_id=%s&client_secret=%s&redirect_uri=%s&code=%s",
		h.config.ClientID,
		h.config.ClientSecret,
		redirectURL,
		code,
	)

	log.Printf("Exchanging code at URL: %s", url)
	log.Printf("Request data (client_id only): grant_type=authorization_code&client_id=%s&redirect_uri=%s", h.config.ClientID, redirectURL)

	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Token exchange request failed: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf("Token exchange response status: %d", resp.StatusCode)

	// Read response body for debugging
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	log.Printf("Token exchange response body: %s", string(bodyBytes))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var token OAuthTokenResponse
	if err := json.Unmarshal(bodyBytes, &token); err != nil {
		return nil, err
	}

	log.Printf("Token received successfully, token type: %s", token.TokenType)
	return &token, nil
}

// getUserInfo fetches user information
func (h *OAuthHandler) getUserInfo(token string) (map[string]interface{}, error) {
	url := strings.TrimSuffix(h.config.APIURL, "/") + "/api/v1/user"

	log.Printf("Getting user info from: %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	// Gitea OAuth2 tokens use "Bearer" authorization
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	log.Printf("Authorization header: Bearer %s...", token[:min(10, len(token))])

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("User info request failed: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf("User info response status: %d", resp.StatusCode)

	// Read response body for debugging
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	log.Printf("User info response body: %s", string(bodyBytes))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// registerWebhooks registers webhooks for all user repositories
func (h *OAuthHandler) registerWebhooks(userToken *UserToken) {
	log.Printf("Registering webhooks for user: %s", userToken.Username)

	// Get user repositories
	repos, err := h.getUserRepositories(userToken.AccessToken)
	if err != nil {
		log.Printf("Failed to get repositories for %s: %v", userToken.Username, err)
		return
	}

	log.Printf("Found %d repositories for %s", len(repos), userToken.Username)

	successCount := 0
	for _, repo := range repos {
		if err := h.registerWebhookForRepo(userToken.AccessToken, repo); err != nil {
			if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "已存在") {
				log.Printf("Webhook already exists for %s", repo)
				successCount++
			} else {
				log.Printf("Failed to register webhook for %s: %v", repo, err)
			}
		} else {
			log.Printf("Webhook registered for %s", repo)
			successCount++
		}
	}

	log.Printf("Webhook registration complete for %s: %d/%d", userToken.Username, successCount, len(repos))
}

// getUserRepositories fetches user's repositories
func (h *OAuthHandler) getUserRepositories(token string) ([]string, error) {
	url := strings.TrimSuffix(h.config.APIURL, "/") + "/api/v1/user/repos?limit=100"

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

	var repos []struct {
		FullName string `json:"full_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
		return nil, err
	}

	var repoNames []string
	for _, repo := range repos {
		repoNames = append(repoNames, repo.FullName)
	}

	return repoNames, nil
}

// registerWebhookForRepo registers a webhook for a specific repository
func (h *OAuthHandler) registerWebhookForRepo(token, repoFullName string) error {
	url := strings.TrimSuffix(h.config.APIURL, "/") + "/api/v1/repos/" + repoFullName + "/hooks"

	payload := map[string]interface{}{
		"type": "gitea",
		"config": map[string]string{
			"url":          h.webhookURL,
			"content_type": "json",
			"secret":       h.secret,
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