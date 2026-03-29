package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
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

	// Setup routes
	router := http.NewServeMux()
	router.HandleFunc("/webhook", deployer.HandleWebhook)
	router.HandleFunc("/health", handleHealth)

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
			// Auto-register webhooks
			go autoRegisterWebhooks(config)
		}
	}
	if config.GiteaSSHKeyPath != "" {
		log.Printf("SSH Key configured: %s", config.GiteaSSHKeyPath)
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK\n")
}