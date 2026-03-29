package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds application configuration from environment variables
type Config struct {
	Domain           string
	WebhookSecret    string
	WebhookPort      int
	PagesDir         string
	EnableHTTPS      bool
	MaxSiteSizeMB    int64
	GiteaAccessToken string
	GiteaAPIURL      string
	GiteaSSHKeyPath  string

	// OAuth2 configuration
	OAuthClientID     string
	OAuthClientSecret string
	OAuthRedirectURL  string
	WebhookPublicURL  string // URL that Gitea can reach for webhooks
	GiteaPublicURL    string // URL that user's browser can reach Gitea
}

// LoadConfig reads configuration from environment variables
func LoadConfig() (*Config, error) {
	port, err := strconv.Atoi(getEnvOrDefault("WEBHOOK_PORT", "8080"))
	if err != nil {
		return nil, fmt.Errorf("invalid WEBHOOK_PORT: %w", err)
	}

	maxSizeMB, err := strconv.ParseInt(getEnvOrDefault("MAX_SITE_SIZE_MB", "100"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid MAX_SITE_SIZE_MB: %w", err)
	}

	enableHTTPS := os.Getenv("ENABLE_HTTPS") == "true"

	return &Config{
		Domain:           getEnvOrDefault("DOMAIN", "yourdomain.com"),
		WebhookSecret:    os.Getenv("WEBHOOK_SECRET"),
		WebhookPort:      port,
		PagesDir:         getEnvOrDefault("PAGES_DATA_DIR", "/var/www/pages"),
		EnableHTTPS:      enableHTTPS,
		MaxSiteSizeMB:    maxSizeMB,
		GiteaAccessToken: os.Getenv("GITEA_ACCESS_TOKEN"),
		GiteaAPIURL:      getEnvOrDefault("GITEA_API_URL", ""),
		GiteaSSHKeyPath:  getEnvOrDefault("GITEA_SSH_KEY_PATH", ""),

		// OAuth2
		OAuthClientID:     os.Getenv("OAUTH_CLIENT_ID"),
		OAuthClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
		OAuthRedirectURL:  os.Getenv("OAUTH_REDIRECT_URL"),
		WebhookPublicURL:  os.Getenv("WEBHOOK_PUBLIC_URL"),
		GiteaPublicURL:    os.Getenv("GITEA_PUBLIC_URL"),
	}, nil
}

func getEnvOrDefault(key, defaultVal string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return val
}

func main() {
	config, err := LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if config.WebhookSecret == "" {
		log.Println("WARNING: WEBHOOK_SECRET not set, signature verification disabled")
	}

	// Initialize deployer
	deployer := NewDeployer(config)

	// Initialize token store for OAuth
	tokenStore := NewTokenStore()

	// Connect token store to deployer for private repo access
	deployer.SetTokenStore(tokenStore)

	// Initialize web handler
	webHandler := NewWebHandler(nil, tokenStore, config.Domain)

	// Initialize OAuth handler if configured
	var oauthHandler *OAuthHandler
	if config.OAuthClientID != "" && config.GiteaAPIURL != "" {
		// Use GiteaPublicURL for browser redirects, GiteaAPIURL for internal API calls
		publicURL := config.GiteaPublicURL
		if publicURL == "" {
			publicURL = config.GiteaAPIURL // fallback to internal URL
		}

		oauthConfig := &OAuthConfig{
			ClientID:        config.OAuthClientID,
			ClientSecret:    config.OAuthClientSecret,
			RedirectURL:     config.OAuthRedirectURL,
			AuthURL:         strings.TrimSuffix(publicURL, "/") + "/login/oauth/authorize",
			TokenURL:        strings.TrimSuffix(config.GiteaAPIURL, "/") + "/login/oauth/access_token",
			APIURL:          config.GiteaAPIURL,
			PublicAuthURL:   strings.TrimSuffix(publicURL, "/") + "/login/oauth/authorize",
		}

		// Use WebhookPublicURL if set, otherwise derive from redirect URL
		webhookURL := config.WebhookPublicURL
		if webhookURL == "" {
			webhookURL = "http://deployer:8080/webhook"
			if config.OAuthRedirectURL != "" {
				// Derive webhook URL from redirect URL for external access
				parts := strings.Split(config.OAuthRedirectURL, "/")
				if len(parts) >= 3 {
					webhookURL = parts[0] + "//" + parts[2] + "/webhook"
				}
			}
		}

		log.Printf("OAuth Auth URL (browser): %s", oauthConfig.PublicAuthURL)
		log.Printf("OAuth Token URL (internal): %s", oauthConfig.TokenURL)
		log.Printf("Webhook URL for OAuth registrations: %s", webhookURL)

		oauthHandler = NewOAuthHandler(oauthConfig, tokenStore, webhookURL, config.WebhookSecret)
		webHandler.oauthConfig = oauthConfig
	}

	// Setup routes
	router := http.NewServeMux()
	router.HandleFunc("/webhook", deployer.HandleWebhook)
	router.HandleFunc("/health", handleHealth)

	// OAuth routes
	if oauthHandler != nil {
		router.HandleFunc("/oauth/start", oauthHandler.HandleStart)
		router.HandleFunc("/oauth/authorize", oauthHandler.HandleAuthorize)
		router.HandleFunc("/oauth/callback", oauthHandler.HandleCallback)
	}

	// Web UI routes
	router.HandleFunc("/", webHandler.HandleIndex)
	router.HandleFunc("/status", webHandler.HandleStatus)

	// Create server with timeouts
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.WebhookPort),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Gitea Pages Deployer starting on port %d", config.WebhookPort)
	log.Printf("Domain: %s, PagesDir: %s, MaxSiteSize: %dMB", config.Domain, config.PagesDir, config.MaxSiteSizeMB)

	if config.GiteaAccessToken != "" {
		log.Printf("Gitea API configured: %s", config.GiteaAPIURL)
		if config.GiteaAPIURL != "" {
			// Auto-register webhooks (legacy mode with global token)
			go autoRegisterWebhooks(config)
		}
	}
	if config.GiteaSSHKeyPath != "" {
		log.Printf("SSH Key configured: %s", config.GiteaSSHKeyPath)
	}

	if config.OAuthClientID != "" {
		log.Printf("OAuth2 enabled: %s", config.GiteaAPIURL)
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK\n")
}