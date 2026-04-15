package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

// WebHandler handles web UI
type WebHandler struct {
	oauthConfig *OAuthConfig
	tokenStore  *TokenStore
	domain      string
	secret      string // For session validation
}

// NewWebHandler creates a new web handler
func NewWebHandler(oauthConfig *OAuthConfig, tokenStore *TokenStore, domain, secret string) *WebHandler {
	return &WebHandler{
		oauthConfig: oauthConfig,
		tokenStore:  tokenStore,
		domain:      domain,
		secret:      secret,
	}
}

// maskUsername masks username for privacy (shows first char only)
func maskUsername(username string) string {
	if len(username) <= 1 {
		return username[:1] + "***"
	}
	return username[:1] + strings.Repeat("*", len(username)-1)
}

// HandleIndex renders the home page
func (h *WebHandler) HandleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		// Let other handlers deal with non-root paths
		return
	}

	hasOAuth := h.oauthConfig != nil && h.oauthConfig.ClientID != ""

	data := struct {
		Domain   string
		HasOAuth bool
	}{
		Domain:   h.domain,
		HasOAuth: hasOAuth,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("index").Parse(indexTemplate))
	tmpl.Execute(w, data)
}

// HandleStatus shows authorization status for the authenticated user only
func (h *WebHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	// Validate session to get authenticated username
	sessionCookie, err := r.Cookie(sessionCookieName)
	authUsername := ""
	if err == nil && sessionCookie != nil {
		authUsername = ValidateSession(sessionCookie, h.secret)
	}

	// If no valid session, show login prompt
	if authUsername == "" {
		h.showStatusLoginPrompt(w, r)
		return
	}

	// Show status for authenticated user only
	h.showUserStatus(w, authUsername)
}

// showStatusLoginPrompt shows a page prompting user to authorize
func (h *WebHandler) showStatusLoginPrompt(w http.ResponseWriter, r *http.Request) {
	hasOAuth := h.oauthConfig != nil && h.oauthConfig.ClientID != ""

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Gitea Pages - Status</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f9fafb; min-height: 100vh; }
        .container { background: white; border-radius: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #3b82f6 0%%, #1d4ed8 100%%); color: white; padding: 40px; text-align: center; }
        .header h1 { margin: 0 0 8px 0; font-size: 28px; }
        .content { padding: 40px; text-align: center; }
        .icon { font-size: 64px; margin-bottom: 20px; }
        .message { color: #6b7280; margin: 20px 0; }
        .btn { display: inline-block; background: #3b82f6; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 500; margin: 10px; }
        .btn:hover { background: #2563eb; }
        .btn-secondary { background: #6b7280; }
        .btn-secondary:hover { background: #4b5563; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Gitea Pages Status</h1>
        </div>
        <div class="content">
            <div class="icon">🔐</div>
            <p class="message">请先授权以查看您的部署状态</p>
            %s
            <p><a href="/" class="btn btn-secondary">返回首页</a></p>
        </div>
    </div>
</body>
</html>
`, func() string {
		if hasOAuth {
			return `<p><a href="/oauth/start" class="btn">授权 Gitea Pages</a></p>`
		}
		return `<p style="color: #dc2626;">OAuth 未配置，请联系管理员</p>`
	}())
}

// showUserStatus shows status for a specific authenticated user
func (h *WebHandler) showUserStatus(w http.ResponseWriter, username string) {
	type UserInfo struct {
		Username   string
		MaskedName string
		RegResult  *WebhookRegistrationResult
	}

	user := UserInfo{
		Username:   username,
		MaskedName: maskUsername(username),
		RegResult:  nil,
	}

	if h.tokenStore != nil {
		user.RegResult = h.tokenStore.GetRegistrationResult(username)
	}

	// Determine status class and text
	var statusClass, statusText string
	if user.RegResult == nil {
		statusClass = "status-pending"
		statusText = "⏳ 正在注册 Webhook..."
	} else if user.RegResult.Success {
		statusClass = "status-success"
		statusText = "✓ " + user.RegResult.Message
	} else if user.RegResult.HasScopeError {
		statusClass = "status-error"
		statusText = "✗ " + user.RegResult.Message
	} else {
		statusClass = "status-warning"
		statusText = "⚠ " + user.RegResult.Message
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Gitea Pages - Status</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f9fafb; min-height: 100vh; }
        .container { background: white; border-radius: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #3b82f6 0%%, #1d4ed8 100%%); color: white; padding: 40px; text-align: center; }
        .header h1 { margin: 0 0 8px 0; font-size: 28px; }
        .content { padding: 40px; }
        .user-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; margin: 20px 0; text-align: center; }
        .user-avatar { width: 64px; height: 64px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); border-radius: 50%%; display: flex; align-items: center; justify-content: center; color: white; font-size: 32px; margin: 0 auto 16px; }
        .user-name { font-weight: 600; color: #1f2937; font-size: 20px; }
        .user-status { font-size: 14px; margin-top: 8px; }
        .status-success { color: #16a34a; }
        .status-warning { color: #d97706; }
        .status-error { color: #dc2626; }
        .status-pending { color: #6b7280; }
        .info-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; margin: 20px 0; }
        .info-card h2 { color: #1f2937; margin: 0 0 16px 0; font-size: 18px; }
        .info-card ul { margin: 0; padding-left: 20px; }
        .info-card li { color: #4b5563; margin: 8px 0; font-size: 14px; }
        .info-card code { background: #e5e7eb; padding: 2px 6px; border-radius: 4px; }
        .btn { display: inline-block; background: #3b82f6; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 500; margin: 10px; }
        .btn:hover { background: #2563eb; }
        .btn-secondary { background: #6b7280; }
        .btn-secondary:hover { background: #4b5563; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 您的授权状态</h1>
        </div>
        <div class="content">
            <div class="user-card">
                <div class="user-avatar">👤</div>
                <div class="user-name">%s</div>
                <div class="user-status %s">%s</div>
            </div>

            <div class="info-card">
                <h2>🌐 站点地址</h2>
                <ul>
                    <li>根目录站点: <code>%s.%s</code></li>
                    <li>子目录站点: <code>%s.%s/repo</code></li>
                </ul>
            </div>

            <div class="info-card">
                <h2>🚀 部署步骤</h2>
                <ul>
                    <li>创建仓库并添加 <code>gh-pages</code> 分支</li>
                    <li>推送代码，自动部署完成</li>
                    <li>删除分支，站点自动移除</li>
                </ul>
            </div>

            <div style="text-align: center;">
                <a href="/" class="btn">← 返回首页</a>
            </div>
        </div>
    </div>
</body>
</html>
`, user.MaskedName, statusClass, statusText, user.Username, h.domain, user.Username, h.domain)
}

// GetUserToken returns a user's token for use in deployments
func (h *WebHandler) GetUserToken(username string) string {
	if h.tokenStore == nil {
		return ""
	}
	token := h.tokenStore.Get(username)
	if token == nil {
		return ""
	}
	return token.AccessToken
}

// GetTokenForRepo returns the token that can access a repository
func (h *WebHandler) GetTokenForRepo(owner string) string {
	return h.GetUserToken(owner)
}

const indexTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Gitea Pages</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background: #f9fafb; min-height: 100vh; }
        .container { max-width: 900px; margin: 0 auto; padding: 20px; }
        .hero { background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%); color: white; border-radius: 16px; padding: 60px 40px; text-align: center; margin-bottom: 32px; }
        .hero h1 { margin: 0 0 12px 0; font-size: 36px; }
        .hero .subtitle { margin: 0; opacity: 0.9; font-size: 18px; }
        .hero-buttons { margin-top: 32px; }
        .btn { display: inline-block; background: white; color: #3b82f6; padding: 14px 28px; border-radius: 8px; text-decoration: none; font-weight: 600; margin: 0 8px; transition: transform 0.2s, box-shadow 0.2s; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .btn-outline { background: transparent; border: 2px solid white; color: white; }
        .btn-outline:hover { background: rgba(255,255,255,0.1); }
        .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 32px 0; }
        .feature { background: white; border-radius: 12px; padding: 32px 24px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); transition: transform 0.2s; }
        .feature:hover { transform: translateY(-4px); }
        .feature-icon { font-size: 48px; margin-bottom: 16px; }
        .feature h3 { color: #1f2937; margin: 0 0 8px 0; font-size: 18px; }
        .feature p { color: #6b7280; font-size: 14px; margin: 0; line-height: 1.6; }
        .card { background: white; border-radius: 16px; padding: 32px; margin: 24px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .card h2 { color: #1f2937; margin: 0 0 20px 0; font-size: 20px; display: flex; align-items: center; gap: 8px; }
        .steps { margin: 0; padding: 0; list-style: none; }
        .steps li { display: flex; align-items: flex-start; margin: 16px 0; }
        .step-number { width: 32px; height: 32px; background: #3b82f6; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 14px; flex-shrink: 0; margin-right: 16px; }
        .step-content { flex: 1; padding-top: 4px; }
        .step-content strong { color: #1f2937; }
        .step-content p { color: #6b7280; margin: 4px 0 0 0; font-size: 14px; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .info-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; }
        .info-box h3 { color: #1f2937; margin: 0 0 12px 0; font-size: 16px; }
        .info-box code { display: block; background: #1f2937; color: #f9fafb; padding: 16px; border-radius: 8px; font-size: 13px; overflow-x: auto; white-space: pre; }
        .info-box ul { margin: 0; padding-left: 20px; }
        .info-box li { color: #4b5563; margin: 8px 0; font-size: 14px; }
        .footer { text-align: center; padding: 40px 20px; color: #6b7280; font-size: 14px; }
        .footer a { color: #3b82f6; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <h1>🚀 Gitea Pages</h1>
            <p class="subtitle">零配置静态网站托管，推送即部署</p>
            {{if .HasOAuth}}
            <div class="hero-buttons">
                <a href="/oauth/start" class="btn">授权 Gitea Pages</a>
                <a href="/status" class="btn btn-outline">查看状态</a>
            </div>
            {{end}}
        </div>

        <div class="features">
            <div class="feature">
                <div class="feature-icon">⚡</div>
                <h3>零配置</h3>
                <p>推送代码到 gh-pages 分支，自动部署完成，无需任何手动操作</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🔒</div>
                <h3>安全可靠</h3>
                <p>支持私有仓库，OAuth2 授权机制，容器化隔离运行</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🌐</div>
                <h3>泛域名路由</h3>
                <p>支持 username.{{.Domain}} 和子目录两种访问方式</p>
            </div>
        </div>

        <div class="card">
            <h2>📋 使用步骤</h2>
            <ol class="steps">
                <li>
                    <span class="step-number">1</span>
                    <div class="step-content">
                        <strong>授权 Gitea Pages</strong>
                        <p>点击上方按钮授权，自动为您的所有仓库注册 Webhook</p>
                    </div>
                </li>
                <li>
                    <span class="step-number">2</span>
                    <div class="step-content">
                        <strong>创建仓库并添加 gh-pages 分支</strong>
                        <p>仓库名为 username.{{.Domain}} 则为根目录站点，其他为子目录站点</p>
                    </div>
                </li>
                <li>
                    <span class="step-number">3</span>
                    <div class="step-content">
                        <strong>推送代码，自动部署完成！</strong>
                        <p>推送后自动触发部署，删除分支则自动移除站点</p>
                    </div>
                </li>
            </ol>
        </div>

        <div class="card">
            <h2>📁 站点地址规则</h2>
            <div class="info-grid">
                <div class="info-box">
                    <h3>🌐 根目录站点</h3>
                    <code>仓库名: username.{{.Domain}}
访问: https://username.{{.Domain}}/</code>
                </div>
                <div class="info-box">
                    <h3>📂 子目录站点</h3>
                    <code>仓库名: 任意名称 (如 my-blog)
访问: https://username.{{.Domain}}/my-blog/</code>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>💡 示例</h2>
            <div class="info-box">
                <code># 创建根目录站点
git init myname.{{.Domain}}
cd myname.{{.Domain}}
git checkout -b gh-pages
echo "&lt;html&gt;&lt;body&gt;Hello!&lt;/body&gt;&lt;/html&gt;" > index.html
git add . && git commit -m "init"
git remote add origin https://gitea.example.com/myname/myname.{{.Domain}}.git
git push -u origin gh-pages

# 访问 https://myname.{{.Domain}}/</code>
            </div>
        </div>

        <div class="footer">
            <p>Gitea Pages · 零配置静态网站托管 · <a href="/status">系统状态</a></p>
        </div>
    </div>
</body>
</html>`