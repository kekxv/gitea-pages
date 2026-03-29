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
// SECURITY: Also checks if token has expired
func (s *TokenStore) GetTokenForRepo(owner string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if token, ok := s.tokens[owner]; ok {
		// Check if token has expired
		if !token.ExpiresAt.IsZero() && time.Now().After(token.ExpiresAt) {
			log.Printf("Token for %s has expired", owner)
			return ""
		}
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
                    <p>在用户级别注册 Webhook，覆盖您所有仓库的推送和删除事件</p>
                </div>
            </div>
            <div class="permission">
                <div class="permission-icon">🏢</div>
                <div class="permission-text">
                    <h4>管理组织 Webhook</h4>
                    <p>为您有权限的组织注册 Webhook，覆盖组织下所有仓库</p>
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
	// SECURITY: Removed write:repository scope - we only need read access for cloning
	// write:repository would allow pushing code, deleting branches, modifying repo settings
	authRedirectURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&state=%s&scope=read:user%%20write:user%%20read:repository%%20write:organization",
		authURL,
		h.config.ClientID,
		redirectURL,
		state,
	)

	log.Printf("OAuth redirect initiated for host: %s", host)
	http.Redirect(w, r, authRedirectURL, http.StatusTemporaryRedirect)
}

// HandleCallback handles the OAuth2 callback
func (h *OAuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		log.Printf("State cookie not found: %v", err)
		http.Error(w, "State cookie not found", http.StatusBadRequest)
		return
	}

	if stateCookie.Value != r.URL.Query().Get("state") {
		log.Printf("OAuth state mismatch")
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
	// Set expiration if provided
	if token.ExpiresIn > 0 {
		userToken.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	h.store.Set(userToken.Username, userToken)

	// Register webhooks synchronously to check for permission issues
	result := h.registerWebhooksWithResult(userToken)

	// Show success page with permission warnings if needed
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if result.HasScopeError {
		fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>授权成功 - 权限不足</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 80px auto; padding: 20px; text-align: center; }
        .warning { color: #f59e0b; font-size: 64px; }
        h1 { color: #1f2937; }
        .info { background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .error-box { background: #fef3c7; border: 1px solid #f59e0b; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .error-box h2 { color: #b45309; margin: 0 0 12px 0; }
        .error-box p { color: #92400e; margin: 8px 0; font-size: 14px; }
        .error-box ul { color: #92400e; margin: 8px 0; padding-left: 20px; font-size: 14px; }
        a { color: #3b82f6; }
        code { background: #e5e7eb; padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="warning">⚠</div>
    <h1>授权成功，但权限不足</h1>
    <div class="info">
        <p><strong>用户:</strong> %s</p>
    </div>
    <div class="error-box">
        <h2>权限问题</h2>
        <p>Webhook 注册失败，需要以下权限：</p>
        <ul>
            <li><code>write:user</code> - 注册用户级 Webhook</li>
            <li><code>write:organization</code> - 注册组织级 Webhook</li>
        </ul>
        <p><strong>解决方法：</strong></p>
        <p>请在 Gitea 中撤销此应用的授权，然后重新授权。</p>
    </div>
    <p><a href="/oauth/start">重新授权</a> | <a href="/">返回首页</a></p>
</body>
</html>
`, userToken.Username)
	} else {
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
        .status { background: #dbeafe; border: 1px solid #3b82f6; padding: 16px; border-radius: 8px; margin: 16px 0; }
        .status p { margin: 4px 0; color: #1e40af; }
        a { color: #3b82f6; }
    </style>
</head>
<body>
    <div class="success">✓</div>
    <h1>授权成功！</h1>
    <div class="info">
        <p><strong>用户:</strong> %s</p>
    </div>
    <div class="status">
        <p>✓ 用户级 Webhook 已注册</p>
        %s
    </div>
    <p>现在你可以推送代码到 <code>gh-pages</code> 分支来自动部署你的网站了。</p>
    <p><a href="/">返回首页</a> | <a href="/status">查看状态</a></p>
</body>
</html>
`, userToken.Username, func() string {
			if result.OrgsFound > 0 {
				return fmt.Sprintf("<p>✓ 组织级 Webhook 已注册 (%d 个组织)</p>", result.OrgsFound)
			}
			return "<p>暂无组织</p>"
		}())
	}
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

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		// SECURITY: Don't log full response body (may contain sensitive info)
		log.Printf("Token exchange failed: status %d", resp.StatusCode)
		return nil, fmt.Errorf("token exchange failed: status %d", resp.StatusCode)
	}

	var token OAuthTokenResponse
	if err := json.Unmarshal(bodyBytes, &token); err != nil {
		return nil, err
	}

	log.Printf("Token received successfully")
	return &token, nil
}

// getUserInfo fetches user information
func (h *OAuthHandler) getUserInfo(token string) (map[string]interface{}, error) {
	url := strings.TrimSuffix(h.config.APIURL, "/") + "/api/v1/user"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	// Gitea OAuth2 tokens use "Bearer" authorization
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("User info request failed: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("User info request failed: status %d", resp.StatusCode)
		return nil, fmt.Errorf("user info request failed: status %d", resp.StatusCode)
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

// WebhookRegistrationResult holds the result of webhook registration
type WebhookRegistrationResult struct {
	UserWebhookError  string
	OrgWebhookErrors  []string
	OrgsFound         int
	HasScopeError     bool
}

// registerWebhooks registers webhooks at user level and organization level
func (h *OAuthHandler) registerWebhooks(userToken *UserToken) {
	result := h.registerWebhooksWithResult(userToken)
	if result.HasScopeError {
		log.Printf("Warning: Scope permission issue detected for %s", userToken.Username)
	}
}

// registerWebhooksWithResult registers webhooks and returns the result
func (h *OAuthHandler) registerWebhooksWithResult(userToken *UserToken) *WebhookRegistrationResult {
	log.Printf("Registering webhooks for: %s", userToken.Username)
	result := &WebhookRegistrationResult{}

	// 1. Register user-level webhook (covers all user's personal repos)
	err := h.registerUserWebhook(userToken.AccessToken)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "已存在") {
			log.Printf("User-level webhook already exists for %s", userToken.Username)
		} else {
			log.Printf("Failed to register user-level webhook for %s: %v", userToken.Username, err)
			result.UserWebhookError = err.Error()
			if strings.Contains(err.Error(), "scope") || strings.Contains(err.Error(), "权限") {
				result.HasScopeError = true
			}
		}
	} else {
		log.Printf("User-level webhook registered for %s", userToken.Username)
	}

	// 2. Register organization-level webhooks (covers all repos in organizations)
	orgs, err := h.getUserOrganizations(userToken.AccessToken)
	if err != nil {
		log.Printf("Failed to get organizations for %s: %v", userToken.Username, err)
		result.OrgWebhookErrors = append(result.OrgWebhookErrors, "获取组织列表失败: "+err.Error())
		if strings.Contains(err.Error(), "scope") || strings.Contains(err.Error(), "权限") {
			result.HasScopeError = true
		}
		return result
	}

	result.OrgsFound = len(orgs)

	if len(orgs) > 0 {
		log.Printf("Found %d organizations for %s", len(orgs), userToken.Username)
		for _, org := range orgs {
			err := h.registerOrgWebhook(userToken.AccessToken, org)
			if err != nil {
				if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "已存在") {
					log.Printf("Organization webhook already exists for %s", org)
				} else {
					log.Printf("Failed to register org webhook for %s: %v", org, err)
					result.OrgWebhookErrors = append(result.OrgWebhookErrors, org+": "+err.Error())
					if strings.Contains(err.Error(), "scope") || strings.Contains(err.Error(), "权限") {
						result.HasScopeError = true
					}
				}
			} else {
				log.Printf("Organization webhook registered for %s", org)
			}
		}
	}

	return result
}

// getUserOrganizations fetches organizations the user belongs to
func (h *OAuthHandler) getUserOrganizations(token string) ([]string, error) {
	url := strings.TrimSuffix(h.config.APIURL, "/") + "/api/v1/user/orgs"

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

	// Read body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Try to parse as array first
	var orgs []struct {
		Username string `json:"username"`
		Name     string `json:"name"`
	}
	if err := json.Unmarshal(bodyBytes, &orgs); err != nil {
		// If that fails, try parsing as single object (some Gitea versions return differently)
		var singleOrg struct {
			Username string `json:"username"`
			Name     string `json:"name"`
		}
		if err2 := json.Unmarshal(bodyBytes, &singleOrg); err2 == nil {
			orgs = []struct {
				Username string `json:"username"`
				Name     string `json:"name"`
			}{singleOrg}
		} else {
			return nil, fmt.Errorf("failed to parse orgs response: %v", err)
		}
	}

	var orgNames []string
	for _, org := range orgs {
		if org.Username != "" {
			orgNames = append(orgNames, org.Username)
		} else if org.Name != "" {
			orgNames = append(orgNames, org.Name)
		}
	}

	return orgNames, nil
}

// registerOrgWebhook registers a webhook at organization level
func (h *OAuthHandler) registerOrgWebhook(token, org string) error {
	url := strings.TrimSuffix(h.config.APIURL, "/") + "/api/v1/orgs/" + org + "/hooks"

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

// registerUserWebhook registers a webhook at user level (covers all repositories)
func (h *OAuthHandler) registerUserWebhook(token string) error {
	url := strings.TrimSuffix(h.config.APIURL, "/") + "/api/v1/user/hooks"

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