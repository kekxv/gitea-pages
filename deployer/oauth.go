package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
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
	Username     string    `json:"username"`
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
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
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	scheme := "http"
	if isSecure {
		scheme = "https"
	}

	// If request comes from a different host, construct redirect URL from request
	if host != "" && !strings.Contains(h.config.RedirectURL, host) {
		redirectURL = fmt.Sprintf("%s://%s/oauth/callback", scheme, host)
	}

	// Store both state and redirect URL in cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_redirect",
		Value:    redirectURL,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})

	// Use PublicAuthURL for browser redirect (different from internal AuthURL)
	authURL := h.config.PublicAuthURL
	if authURL == "" {
		authURL = h.config.AuthURL // fallback
	}

	// Redirect to OAuth provider
	// SECURITY: Removed write:repository scope - we only need read access for cloning
	// write:repository would allow pushing code, deleting branches, modifying repo settings
	// Added access_type=offline to get refresh_token for automatic token renewal
	authRedirectURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&state=%s&scope=read:user%%20write:user%%20read:repository%%20write:organization&access_type=offline",
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
	// Determine if connection is secure
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

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
		Username:     userInfo["login"].(string),
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		CreatedAt:    time.Now(),
	}
	// Set expiration if provided
	if token.ExpiresIn > 0 {
		userToken.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	h.store.Set(userToken.Username, userToken)

	// Register webhooks asynchronously to avoid timeout for users with many organizations
	go h.registerWebhooks(userToken)

	// Set session cookie for /status page authentication
	// Session contains signed username to prevent forgery
	sessionCookie := h.createSessionCookie(userToken.Username, isSecure)
	http.SetCookie(w, sessionCookie)

	// Show success page immediately
	// SECURITY: Mask username to prevent information leakage
	maskedUsername := maskUsername(userToken.Username)
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
        .status { background: #dbeafe; border: 1px solid #3b82f6; padding: 16px; border-radius: 8px; margin: 16px 0; }
        .status p { margin: 4px 0; color: #1e40af; }
        a { color: #3b82f6; }
        code { background: #e5e7eb; padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="success">✓</div>
    <h1>授权成功！</h1>
    <div class="info">
        <p><strong>用户:</strong> %s</p>
    </div>
    <div class="status">
        <p>⏳ 正在后台注册 Webhook...</p>
        <p style="font-size: 12px; color: #6b7280;">如果您的组织较多，可能需要几秒钟</p>
    </div>
    <p>现在你可以推送代码到 <code>gh-pages</code> 分支来自动部署你的网站了。</p>
    <p><a href="/">返回首页</a> | <a href="/status">查看状态</a></p>
</body>
</html>
`, maskedUsername)
}

// OAuthTokenResponse represents the token response
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
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

// refreshAccessToken refreshes an expired access token using the refresh token
// Returns the new token response or error
func (h *OAuthHandler) refreshAccessToken(refreshToken string) (*OAuthTokenResponse, error) {
	url := h.config.TokenURL

	data := fmt.Sprintf("grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s",
		h.config.ClientID,
		h.config.ClientSecret,
		refreshToken,
	)

	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Token refresh request failed: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Token refresh failed: status %d", resp.StatusCode)
		return nil, fmt.Errorf("token refresh failed: status %d", resp.StatusCode)
	}

	var token OAuthTokenResponse
	if err := json.Unmarshal(bodyBytes, &token); err != nil {
		return nil, err
	}

	log.Printf("Token refreshed successfully")
	return &token, nil
}

// RefreshAllTokens refreshes all stored tokens proactively
// This is called periodically to prevent tokens from expiring
func (h *OAuthHandler) RefreshAllTokens() {
	if h.store == nil {
		return
	}

	users := h.store.List()
	for _, username := range users {
		token := h.store.Get(username)
		if token == nil {
			continue
		}

		// Skip if no refresh token available
		if token.RefreshToken == "" {
			log.Printf("No refresh token for %s, user needs to re-authorize", username)
			continue
		}

		// Check if token needs refresh (expires within 7 days or already expired)
		shouldRefresh := false
		if token.ExpiresAt.IsZero() {
			// No expiration set, refresh anyway to be safe
			shouldRefresh = true
		} else if time.Now().Add(7 * 24 * time.Hour).After(token.ExpiresAt) {
			// Expires within 7 days, refresh now
			shouldRefresh = true
		}

		if !shouldRefresh {
			continue
		}

		log.Printf("Proactively refreshing token for %s (expires at %s)", username, token.ExpiresAt.Format("2006-01-02 15:04:05"))

		newToken, err := h.refreshAccessToken(token.RefreshToken)
		if err != nil {
			log.Printf("Failed to refresh token for %s: %v", username, err)
			// Token refresh failed, user needs to re-authorize
			continue
		}

		// Update token in store
		token.AccessToken = newToken.AccessToken
		token.TokenType = newToken.TokenType
		if newToken.RefreshToken != "" {
			token.RefreshToken = newToken.RefreshToken
		}
		if newToken.ExpiresIn > 0 {
			token.ExpiresAt = time.Now().Add(time.Duration(newToken.ExpiresIn) * time.Second)
		}
		token.CreatedAt = time.Now()
		h.store.Set(username, token)

		log.Printf("Token refreshed successfully for %s", username)
	}
}

// StartBackgroundRefresh starts a background goroutine that periodically refreshes tokens
// interval is the time between refresh checks (in hours)
func (h *OAuthHandler) StartBackgroundRefresh(intervalHours int) {
	if h.store == nil {
		return
	}

	// Refresh immediately on startup
	log.Printf("Starting initial token refresh check...")
	h.RefreshAllTokens()

	// Start background refresh loop
	go func() {
		ticker := time.NewTicker(time.Duration(intervalHours) * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			log.Printf("Running scheduled token refresh check...")
			h.RefreshAllTokens()
		}
	}()

	log.Printf("Background token refresh started (interval: %d hours)", intervalHours)
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
	Success           bool
	Message           string
}

// registerWebhooks registers webhooks at user level and organization level
func (h *OAuthHandler) registerWebhooks(userToken *UserToken) {
	result := h.registerWebhooksWithResult(userToken)

	// Store result in token store for status page to display
	if h.store != nil {
		h.store.SetRegistrationResult(userToken.Username, result)
	}

	if result.HasScopeError {
		log.Printf("Warning: Scope permission issue detected for %s", userToken.Username)
	}
}

// registerWebhooksWithResult registers webhooks and returns the result
func (h *OAuthHandler) registerWebhooksWithResult(userToken *UserToken) *WebhookRegistrationResult {
	log.Printf("Registering webhooks for: %s", userToken.Username)
	result := &WebhookRegistrationResult{}

	// 1. Register user-level webhook (covers all user's personal repos)
	err := h.registerUserWebhook(userToken.AccessToken, userToken.Username)
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
			err := h.registerOrgWebhook(userToken.AccessToken, org, userToken.Username)
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

	// Set success status and message
	result.Success = !result.HasScopeError && result.UserWebhookError == "" && len(result.OrgWebhookErrors) == 0
	if result.HasScopeError {
		result.Message = "权限不足，请在 Gitea 中撤销授权后重新授权"
	} else if result.UserWebhookError != "" {
		result.Message = "用户级 Webhook 注册失败: " + result.UserWebhookError
	} else if len(result.OrgWebhookErrors) > 0 {
		result.Message = fmt.Sprintf("部分组织 Webhook 注册失败 (%d/%d)", len(result.OrgWebhookErrors), result.OrgsFound)
	} else if result.OrgsFound > 0 {
		result.Message = fmt.Sprintf("Webhook 注册成功 (用户 + %d 个组织)", result.OrgsFound)
	} else {
		result.Message = "用户级 Webhook 注册成功"
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

// webhookConfig represents webhook config for comparison
type webhookConfig struct {
	URL string `json:"url"`
}

// webhookInfo represents webhook info from API
type webhookInfo struct {
	ID                 int64         `json:"id"`
	Type               string        `json:"type"`
	Config             webhookConfig `json:"config"`
	Events             []string      `json:"events"`
	Active             bool          `json:"active"`
	AuthorizationHeader string        `json:"authorization_header"`
}

// checkUserWebhookExists checks if a webhook with the same URL already exists
// Returns: (webhookID, authorizationHeader, error)
// If not found: (0, "", nil)
func (h *OAuthHandler) checkUserWebhookExists(token string) (int64, string, error) {
	url := strings.TrimSuffix(h.config.APIURL, "/") + "/api/v1/user/hooks"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, "", nil // If we can't list, proceed to create
	}

	var webhooks []webhookInfo
	if err := json.NewDecoder(resp.Body).Decode(&webhooks); err != nil {
		return 0, "", err
	}

	for _, wh := range webhooks {
		if wh.Config.URL == h.webhookURL {
			return wh.ID, wh.AuthorizationHeader, nil
		}
	}

	return 0, "", nil
}

// checkOrgWebhookExists checks if a webhook with the same URL already exists for org
// Returns: (webhookID, authorizationHeader, error)
// If not found: (0, "", nil)
func (h *OAuthHandler) checkOrgWebhookExists(token, org string) (int64, string, error) {
	url := strings.TrimSuffix(h.config.APIURL, "/") + "/api/v1/orgs/" + org + "/hooks"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, "", nil // If we can't list, proceed to create
	}

	var webhooks []webhookInfo
	if err := json.NewDecoder(resp.Body).Decode(&webhooks); err != nil {
		return 0, "", err
	}

	for _, wh := range webhooks {
		if wh.Config.URL == h.webhookURL {
			return wh.ID, wh.AuthorizationHeader, nil
		}
	}

	return 0, "", nil
}

// updateOrgWebhook updates an existing organization-level webhook
func (h *OAuthHandler) updateOrgWebhook(token string, org string, id int64, payload map[string]interface{}) error {
	url := fmt.Sprintf("%s/api/v1/orgs/%s/hooks/%d", strings.TrimSuffix(h.config.APIURL, "/"), org, id)

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PATCH", url, strings.NewReader(string(body)))
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

// updateUserWebhook updates an existing user-level webhook
func (h *OAuthHandler) updateUserWebhook(token string, id int64, payload map[string]interface{}) error {
	url := fmt.Sprintf("%s/api/v1/user/hooks/%d", strings.TrimSuffix(h.config.APIURL, "/"), id)

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PATCH", url, strings.NewReader(string(body)))
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

// registerOrgWebhook registers a webhook at organization level
// username is used to construct the authorization_header for webhook
func (h *OAuthHandler) registerOrgWebhook(token, org, username string) error {
	// Construct authorization header with user info (base64 encoded JSON)
	userInfo := map[string]string{"username": username}
	userInfoJSON, _ := json.Marshal(userInfo)
	authHeader := "Bearer " + base64.StdEncoding.EncodeToString(userInfoJSON)

	payload := map[string]interface{}{
		"type": "gitea",
		"config": map[string]string{
			"url":          h.webhookURL,
			"content_type": "json",
			"secret":       h.secret,
		},
		"events":              []string{"push", "delete"},
		"active":              true,
		"branch_filter":       "gh-pages",
		"authorization_header": authHeader,
	}

	// Check if webhook already exists
	existingID, existingHeader, err := h.checkOrgWebhookExists(token, org)
	if err != nil {
		log.Printf("Warning: failed to check existing org webhooks: %v", err)
	}

	if existingID > 0 {
		// If exists with same authorization_header, skip
		if existingHeader == authHeader {
			log.Printf("Webhook already exists for org %s with same config, skipping", org)
			return nil
		}
		// If exists but config different, update
		log.Printf("Webhook exists for org %s with different config, updating...", org)
		return h.updateOrgWebhook(token, org, existingID, payload)
	}

	// Create new webhook
	url := strings.TrimSuffix(h.config.APIURL, "/") + "/api/v1/orgs/" + org + "/hooks"

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
// username is used to construct the authorization_header for webhook
func (h *OAuthHandler) registerUserWebhook(token, username string) error {
	// Construct authorization header with user info (base64 encoded JSON)
	userInfo := map[string]string{"username": username}
	userInfoJSON, _ := json.Marshal(userInfo)
	authHeader := "Bearer " + base64.StdEncoding.EncodeToString(userInfoJSON)

	payload := map[string]interface{}{
		"type": "gitea",
		"config": map[string]string{
			"url":          h.webhookURL,
			"content_type": "json",
			"secret":       h.secret,
		},
		"events":              []string{"push", "delete"},
		"active":              true,
		"branch_filter":       "gh-pages",
		"authorization_header": authHeader,
	}

	// Check if webhook already exists
	existingID, existingHeader, err := h.checkUserWebhookExists(token)
	if err != nil {
		log.Printf("Warning: failed to check existing user webhooks: %v", err)
	}

	if existingID > 0 {
		// If exists with same authorization_header, skip
		if existingHeader == authHeader {
			log.Printf("Webhook already exists for user with same config, skipping")
			return nil
		}
		// If exists but config different, update
		log.Printf("Webhook exists for user with different config, updating...")
		return h.updateUserWebhook(token, existingID, payload)
	}

	// Create new webhook
	url := strings.TrimSuffix(h.config.APIURL, "/") + "/api/v1/user/hooks"

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
// Session cookie constants
const (
	sessionCookieName = "gitea_pages_session"
	sessionDuration   = 24 * time.Hour // 24 hours
)

// createSessionCookie creates a signed session cookie containing the username
// The cookie value is: username:timestamp:HMAC signature
func (h *OAuthHandler) createSessionCookie(username string, secure bool) *http.Cookie {
	// Create session value: username:timestamp
	sessionData := fmt.Sprintf("%s:%d", username, time.Now().Unix())

	// Sign the session data with HMAC
	signature := h.signSession(sessionData)

	// Combine data and signature
	cookieValue := fmt.Sprintf("%s:%s", sessionData, signature)

	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookieValue,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// signSession creates an HMAC signature for session data
func (h *OAuthHandler) signSession(data string) string {
	if h.secret == "" {
		// No secret configured, use a fallback (not ideal but prevents crash)
		return ""
	}
	mac := hmac.New(sha256.New, []byte(h.secret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateSession validates a session cookie and returns the username
// Returns empty string if invalid
func ValidateSession(cookie *http.Cookie, secret string) string {
	if cookie == nil || cookie.Value == "" || secret == "" {
		return ""
	}

	// Parse cookie value: username:timestamp:signature
	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 3 {
		return ""
	}

	username := parts[0]
	timestampStr := parts[1]
	signature := parts[2]

	// Verify signature
	expectedSig := signSessionWithSecret(fmt.Sprintf("%s:%s", username, timestampStr), secret)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return ""
	}

	// Check timestamp (prevent expired sessions)
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return ""
	}
	if time.Now().Unix()-timestamp > int64(sessionDuration.Seconds()) {
		return ""
	}

	return username
}

// signSessionWithSecret signs session data with a specific secret
func signSessionWithSecret(data, secret string) string {
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}
