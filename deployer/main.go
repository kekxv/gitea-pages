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
	EnableHTTPS             bool
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

	enableOrganizationHooks, err := boolEnv("ENABLE_ORGANIZATION_HOOKS", true)
	if err != nil {
		return nil, err
	}
	appEnv := os.Getenv("APP_ENV")
	giteaAPIURL := os.Getenv("GITEA_API_URL")
	if err := validateGiteaURL(giteaAPIURL, appEnv); err != nil {
		return nil, err
	}
	giteaPublicURL := os.Getenv("GITEA_PUBLIC_URL")
	if giteaPublicURL != "" {
		if err := validateGiteaURL(giteaPublicURL, appEnv); err != nil {
			return nil, fmt.Errorf("invalid GITEA_PUBLIC_URL: %w", err)
		}
	}
	if err := validateOptionalPublicURL("OAUTH_REDIRECT_URL", os.Getenv("OAUTH_REDIRECT_URL"), appEnv); err != nil {
		return nil, err
	}
	if err := validateOptionalPublicURL("WEBHOOK_PUBLIC_URL", os.Getenv("WEBHOOK_PUBLIC_URL"), appEnv); err != nil {
		return nil, err
	}

	sessionSecret, err := loadOptionalSecretFile(os.Getenv("SESSION_SECRET_FILE"), os.Getenv("SESSION_SECRET"))
	if err != nil {
		return nil, fmt.Errorf("SESSION_SECRET_FILE: %w", err)
	}
	if len(sessionSecret) < 32 {
		return nil, errors.New("SESSION_SECRET_FILE or SESSION_SECRET must contain at least 32 bytes")
	}

	tokenEncryptionKey, err := loadOptionalSecretFile(os.Getenv("TOKEN_ENCRYPTION_KEY_FILE"), "")
	if err != nil {
		return nil, fmt.Errorf("TOKEN_ENCRYPTION_KEY_FILE: %w", err)
	}
	if len(tokenEncryptionKey) == 0 {
		return nil, errors.New("TOKEN_ENCRYPTION_KEY_FILE is required")
	}
	if len(tokenEncryptionKey) != 32 {
		return nil, errors.New("TOKEN_ENCRYPTION_KEY_FILE must contain exactly 32 bytes")
	}

	oauthClientSecret, err := loadOAuthClientSecret(os.Getenv("OAUTH_CLIENT_ID"), os.Getenv("OAUTH_CLIENT_SECRET_FILE"), os.Getenv("OAUTH_CLIENT_SECRET"))
	if err != nil {
		return nil, err
	}
	enableHTTPS := os.Getenv("ENABLE_HTTPS") == "true"

	return &Config{
		Domain:                  getEnvOrDefault("DOMAIN", "pages.yourdomain.com"),
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

func loadOptionalSecretFile(path, legacyValue string) ([]byte, error) {
	if path == "" {
		return []byte(legacyValue), nil
	}
	return readSecretFile(path)
}

func loadOAuthClientSecret(clientID, path, legacyValue string) (string, error) {
	if path == "" {
		if clientID != "" && legacyValue == "" {
			return "", errors.New("OAUTH_CLIENT_SECRET_FILE or OAUTH_CLIENT_SECRET is required when OAUTH_CLIENT_ID is set")
		}
		return legacyValue, nil
	}
	secret, err := readSecretFile(path)
	if err != nil {
		return "", fmt.Errorf("OAUTH_CLIENT_SECRET_FILE: %w", err)
	}
	return string(secret), nil
}

func validateGiteaURL(rawURL, appEnv string) error {
	return validateConfiguredURL("GITEA_API_URL", rawURL, appEnv, true)
}

func validateOptionalPublicURL(name, rawURL, appEnv string) error {
	return validateConfiguredURL(name, rawURL, appEnv, false)
}

func validateConfiguredURL(name, rawURL, appEnv string, required bool) error {
	if rawURL == "" {
		if required {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}
	parsed, err := parseHTTPURL(rawURL)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	if parsed.Scheme == "http" && (appEnv != "development" || !isLocalDevelopmentHost(parsed.Hostname())) {
		return fmt.Errorf("%s must use HTTPS outside local development", name)
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
	host = strings.ToLower(host)
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return host != "" && !strings.Contains(host, ".") && !strings.Contains(host, ":")
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

func oauthConfigFromAppConfig(config *Config) *OAuthConfig {
	publicURL := config.GiteaPublicURL
	if publicURL == "" {
		publicURL = config.GiteaAPIURL
	}
	return &OAuthConfig{
		ClientID:                 config.OAuthClientID,
		ClientSecret:             config.OAuthClientSecret,
		RedirectURL:              config.OAuthRedirectURL,
		AuthURL:                  strings.TrimSuffix(publicURL, "/") + "/login/oauth/authorize",
		TokenURL:                 strings.TrimSuffix(config.GiteaAPIURL, "/") + "/login/oauth/access_token",
		APIURL:                   config.GiteaAPIURL,
		PublicAuthURL:            strings.TrimSuffix(publicURL, "/") + "/login/oauth/authorize",
		DisableOrganizationHooks: !config.EnableOrganizationHooks,
	}
}

func main() {
	if handled, err := runSecurityMigrationCommand(os.Args[1:]); handled {
		if err != nil {
			log.Printf("Security migration command failed: %v", err)
			os.Exit(1)
		}
		return
	}

	config, err := LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize token store for OAuth with SQLite persistence
	tokenStore, err := NewTokenStore(config.DataDir, config.TokenEncryptionKey)
	if err != nil {
		log.Fatalf("Failed to initialize encrypted token store: %v", err)
	}

	// Webhooks are enabled only after encrypted token and per-hook credential
	// storage exists. There is no runtime shared-secret fallback after migration.
	repositoryVerifier, err := NewRepositoryVerifier(config.GiteaAPIURL, tokenStore)
	if err != nil {
		log.Fatalf("Failed to initialize repository verifier: %v", err)
	}
	deployer := NewWebhookDeployer(config, tokenStore, repositoryVerifier, NewDeploymentService(config))

	// Initialize web handler
	webHandler := NewWebHandler(nil, tokenStore, config.Domain, string(config.SessionSecret))

	// Initialize OAuth handler if configured
	var oauthHandler *OAuthHandler
	if config.OAuthClientID != "" && config.GiteaAPIURL != "" {
		oauthConfig := oauthConfigFromAppConfig(config)

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

		oauthHandler = NewOAuthHandler(oauthConfig, tokenStore, webhookURL, string(config.SessionSecret))
		webHandler.oauthConfig = oauthConfig
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
