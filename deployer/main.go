package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds application configuration from environment variables
type Config struct {
	Domain                  string
	WebhookPort             int
	PagesDir                string
	DataDir                 string // Directory for persistent data (tokens.db, etc.)
	GiteaAPIURL             string
	GiteaPublicURL          string
	OAuthClientID           string
	OAuthClientSecret       string
	OAuthRedirectURL        string
	WebhookPublicURL        string // URL that Gitea can reach for webhooks
	SessionSecret           []byte
	TokenEncryptionKey      []byte
	CloneTimeout            time.Duration
	AcquireTimeout          time.Duration
	MaxConcurrentDeploys    int
	MaxSiteSizeMB           int64
	MaxRepositorySizeMB     int64
	EnableOrganizationHooks bool

	// Deprecated compatibility fields. LoadConfig deliberately does not fill
	// WebhookSecret: normal server mode must not accept a global webhook secret.
	WebhookSecret    string
	EnableHTTPS      bool
	GiteaAccessToken string
	GiteaSSHKeyPath  string
}

// LoadConfig reads configuration from environment variables
func LoadConfig() (*Config, error) {
	port, err := positiveInt("WEBHOOK_PORT", getEnvOrDefault("WEBHOOK_PORT", "8080"))
	if err != nil {
		return nil, err
	}

	maxSizeMB, err := positiveInt64("MAX_SITE_SIZE_MB", getEnvOrDefault("MAX_SITE_SIZE_MB", "100"))
	if err != nil {
		return nil, err
	}

	maxRepositorySizeMB, err := positiveInt64("MAX_REPOSITORY_SIZE_MB", getEnvOrDefault("MAX_REPOSITORY_SIZE_MB", "1024"))
	if err != nil {
		return nil, err
	}

	maxConcurrentDeploys, err := positiveInt("MAX_CONCURRENT_DEPLOYS", getEnvOrDefault("MAX_CONCURRENT_DEPLOYS", "4"))
	if err != nil {
		return nil, err
	}
	if maxConcurrentDeploys > 32 {
		return nil, fmt.Errorf("MAX_CONCURRENT_DEPLOYS must be between 1 and 32")
	}

	cloneTimeout, err := time.ParseDuration(getEnvOrDefault("CLONE_TIMEOUT", "1m"))
	if err != nil || cloneTimeout < 10*time.Second || cloneTimeout > 10*time.Minute {
		return nil, fmt.Errorf("CLONE_TIMEOUT must be between 10s and 10m")
	}

	acquireTimeout, err := time.ParseDuration(getEnvOrDefault("ACQUIRE_TIMEOUT", "30s"))
	if err != nil || acquireTimeout <= 0 {
		return nil, fmt.Errorf("ACQUIRE_TIMEOUT must be a positive duration")
	}

	enableOrganizationHooks, err := boolEnv("ENABLE_ORGANIZATION_HOOKS", false)
	if err != nil {
		return nil, err
	}

	giteaAPIURL := os.Getenv("GITEA_API_URL")
	if err := validateGiteaURL(giteaAPIURL, os.Getenv("APP_ENV")); err != nil {
		return nil, err
	}
	giteaPublicURL := os.Getenv("GITEA_PUBLIC_URL")
	if giteaPublicURL != "" {
		if err := validateGiteaURL(giteaPublicURL, os.Getenv("APP_ENV")); err != nil {
			return nil, fmt.Errorf("invalid GITEA_PUBLIC_URL: %w", err)
		}
	}
	if err := validateOptionalHTTPURL("OAUTH_REDIRECT_URL", os.Getenv("OAUTH_REDIRECT_URL")); err != nil {
		return nil, err
	}
	if err := validateOptionalHTTPURL("WEBHOOK_PUBLIC_URL", os.Getenv("WEBHOOK_PUBLIC_URL")); err != nil {
		return nil, err
	}

	sessionSecret, err := readSecretFile(os.Getenv("SESSION_SECRET_FILE"))
	if err != nil {
		return nil, fmt.Errorf("SESSION_SECRET_FILE: %w", err)
	}
	if len(sessionSecret) < 32 {
		return nil, errors.New("SESSION_SECRET_FILE must contain at least 32 bytes")
	}

	tokenEncryptionKey, err := readSecretFile(os.Getenv("TOKEN_ENCRYPTION_KEY_FILE"))
	if err != nil {
		return nil, fmt.Errorf("TOKEN_ENCRYPTION_KEY_FILE: %w", err)
	}
	if len(tokenEncryptionKey) != 32 {
		return nil, errors.New("TOKEN_ENCRYPTION_KEY_FILE must contain exactly 32 bytes")
	}

	oauthClientSecret, err := loadOAuthClientSecret(os.Getenv("OAUTH_CLIENT_ID"), os.Getenv("OAUTH_CLIENT_SECRET_FILE"))
	if err != nil {
		return nil, err
	}

	enableHTTPS := os.Getenv("ENABLE_HTTPS") == "true"

	return &Config{
		Domain:                  getEnvOrDefault("DOMAIN", "yourdomain.com"),
		WebhookPort:             port,
		PagesDir:                getEnvOrDefault("PAGES_DATA_DIR", "/var/www/pages"),
		DataDir:                 getEnvOrDefault("DEPLOYER_DATA_DIR", "/var/lib/deployer"),
		GiteaAPIURL:             giteaAPIURL,
		GiteaPublicURL:          giteaPublicURL,
		OAuthClientID:           os.Getenv("OAUTH_CLIENT_ID"),
		OAuthClientSecret:       oauthClientSecret,
		OAuthRedirectURL:        os.Getenv("OAUTH_REDIRECT_URL"),
		WebhookPublicURL:        os.Getenv("WEBHOOK_PUBLIC_URL"),
		SessionSecret:           sessionSecret,
		TokenEncryptionKey:      tokenEncryptionKey,
		CloneTimeout:            cloneTimeout,
		AcquireTimeout:          acquireTimeout,
		MaxConcurrentDeploys:    maxConcurrentDeploys,
		MaxSiteSizeMB:           maxSizeMB,
		MaxRepositorySizeMB:     maxRepositorySizeMB,
		EnableOrganizationHooks: enableOrganizationHooks,
		EnableHTTPS:             enableHTTPS,
		GiteaAccessToken:        os.Getenv("GITEA_ACCESS_TOKEN"),
		GiteaSSHKeyPath:         getEnvOrDefault("GITEA_SSH_KEY_PATH", ""),
	}, nil
}

func readSecretFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read secret file: %w", err)
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, errors.New("secret file is empty")
	}
	return b, nil
}

func loadOAuthClientSecret(clientID, path string) (string, error) {
	if path == "" {
		if clientID != "" {
			return "", errors.New("OAUTH_CLIENT_SECRET_FILE is required when OAUTH_CLIENT_ID is set")
		}
		return "", nil
	}
	secret, err := readSecretFile(path)
	if err != nil {
		return "", fmt.Errorf("OAUTH_CLIENT_SECRET_FILE: %w", err)
	}
	return string(secret), nil
}

func validateGiteaURL(rawURL, appEnv string) error {
	if rawURL == "" {
		return errors.New("GITEA_API_URL is required")
	}
	parsed, err := parseHTTPURL(rawURL)
	if err != nil {
		return fmt.Errorf("invalid GITEA_API_URL: %w", err)
	}
	if parsed.Scheme == "http" && (appEnv != "development" || !isLocalDevelopmentHost(parsed.Hostname())) {
		return errors.New("GITEA_API_URL must use HTTPS outside local development")
	}
	return nil
}

func validateOptionalHTTPURL(name, rawURL string) error {
	if rawURL == "" {
		return nil
	}
	if _, err := parseHTTPURL(rawURL); err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	return nil
}

func parseHTTPURL(rawURL string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("must be an absolute HTTP(S) URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("must use HTTP or HTTPS")
	}
	return parsed, nil
}

func isLocalDevelopmentHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host != "" && !strings.Contains(host, ".")
}

func positiveInt(name, value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func positiveInt64(name, value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func boolEnv(name string, defaultValue bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid %s: %w", name, err)
	}
	return parsed, nil
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

	// Initialize deployer
	deployer := NewDeployer(config)

	// Initialize token store for OAuth with SQLite persistence
	tokenStore := NewTokenStore(config.DataDir)

	// Connect token store to deployer for private repo access
	deployer.SetTokenStore(tokenStore)

	// Initialize web handler
	webHandler := NewWebHandler(nil, tokenStore, config.Domain, "")

	// Initialize OAuth handler if configured
	var oauthHandler *OAuthHandler
	if config.OAuthClientID != "" && config.GiteaAPIURL != "" {
		// Use GiteaPublicURL for browser redirects, GiteaAPIURL for internal API calls
		publicURL := config.GiteaPublicURL
		if publicURL == "" {
			publicURL = config.GiteaAPIURL // fallback to internal URL
		}

		oauthConfig := &OAuthConfig{
			ClientID:      config.OAuthClientID,
			ClientSecret:  config.OAuthClientSecret,
			RedirectURL:   config.OAuthRedirectURL,
			AuthURL:       strings.TrimSuffix(publicURL, "/") + "/login/oauth/authorize",
			TokenURL:      strings.TrimSuffix(config.GiteaAPIURL, "/") + "/login/oauth/access_token",
			APIURL:        config.GiteaAPIURL,
			PublicAuthURL: strings.TrimSuffix(publicURL, "/") + "/login/oauth/authorize",
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

		oauthHandler = NewOAuthHandler(oauthConfig, tokenStore, webhookURL, "")
		webHandler.oauthConfig = oauthConfig
		deployer.SetOAuthHandler(oauthHandler)

		// Start background token refresh (every 24 hours)
		// This proactively refreshes tokens before they expire
		oauthHandler.StartBackgroundRefresh(24)
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
