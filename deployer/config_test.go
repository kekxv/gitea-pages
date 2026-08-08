package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigRejectsMissingSecurityValues(t *testing.T) {
	t.Setenv("GITEA_API_URL", "")
	t.Setenv("SESSION_SECRET_FILE", "")
	t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", "")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig must reject missing GITEA_API_URL and secret files")
	}
}

func TestLoadConfigRejectsNonHTTPSGiteaOutsideDevelopment(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("GITEA_API_URL", "http://gitea.example.com")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("production Gitea URL must use HTTPS")
	}
}

func TestLoadConfigRejectsMissingSessionSecretWithValidGitea(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("GITEA_API_URL", "https://gitea.example.com")
	t.Setenv("SESSION_SECRET_FILE", "")
	t.Setenv("SESSION_SECRET", "")
	t.Setenv("OAUTH_CLIENT_ID", "")
	t.Setenv("OAUTH_CLIENT_SECRET_FILE", "")
	t.Setenv("OAUTH_CLIENT_SECRET", "")
	t.Setenv("LEGACY_WEBHOOK_SECRET_FILE", "")
	t.Setenv("WEBHOOK_SECRET", "")

	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig must reject a valid Gitea configuration with no session secret")
	}
}

func TestLoadConfigPrefersLegacyWebhookSecretFile(t *testing.T) {
	dir := t.TempDir()
	sessionSecret := writeTestSecretFile(t, dir, "session", strings.Repeat("s", 32)+"\n")
	encryptionKey := writeTestSecretFile(t, dir, "key", strings.Repeat("k", 32)+"\n")
	legacyWebhookSecret := writeTestSecretFile(t, dir, "legacy-webhook", "file-webhook-secret\n")

	t.Setenv("APP_ENV", "production")
	t.Setenv("GITEA_API_URL", "https://gitea.example.com")
	t.Setenv("SESSION_SECRET_FILE", sessionSecret)
	t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", encryptionKey)
	t.Setenv("LEGACY_WEBHOOK_SECRET_FILE", legacyWebhookSecret)
	t.Setenv("WEBHOOK_SECRET", "environment-webhook-secret")

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if got, want := string(config.SessionSecret), strings.Repeat("s", 32); got != want {
		t.Errorf("SessionSecret = %q, want %q", got, want)
	}
	if got, want := string(config.TokenEncryptionKey), strings.Repeat("k", 32); got != want {
		t.Errorf("TokenEncryptionKey = %q, want %q", got, want)
	}
	if got, want := config.WebhookSecret, "file-webhook-secret"; got != want {
		t.Errorf("WebhookSecret = %q, want %q", got, want)
	}
	if !config.LegacyHooksEnabled {
		t.Error("LegacyHooksEnabled = false, want true when a legacy webhook secret is configured")
	}
}

func TestLoadConfigAllowsLocalHTTPGiteaOnlyInDevelopment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "development")
	t.Setenv("GITEA_API_URL", "http://gitea")
	t.Setenv("SESSION_SECRET_FILE", writeTestSecretFile(t, dir, "session", strings.Repeat("s", 32)))
	t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", writeTestSecretFile(t, dir, "key", strings.Repeat("k", 32)))

	if _, err := LoadConfig(); err != nil {
		t.Fatalf("LoadConfig() error = %v, want local development HTTP URL to be accepted", err)
	}
}

func TestLoadConfigRejectsNonExactLoopbackGiteaHost(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "development")
	t.Setenv("GITEA_API_URL", "http://127.0.0.2:3000")
	t.Setenv("SESSION_SECRET_FILE", writeTestSecretFile(t, dir, "session", strings.Repeat("s", 32)))
	t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", writeTestSecretFile(t, dir, "key", strings.Repeat("k", 32)))

	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig must reject non-exact loopback hosts over HTTP")
	}
}

func TestLoadConfigEnablesOrganizationHooksByDefault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "production")
	t.Setenv("GITEA_API_URL", "https://gitea.example.com")
	t.Setenv("SESSION_SECRET_FILE", writeTestSecretFile(t, dir, "session", strings.Repeat("s", 32)))
	t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", writeTestSecretFile(t, dir, "key", strings.Repeat("k", 32)))
	t.Setenv("ENABLE_ORGANIZATION_HOOKS", "")

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if !config.EnableOrganizationHooks {
		t.Error("EnableOrganizationHooks = false, want true by default")
	}
}

func TestLoadConfigUsesLegacySessionAndOAuthSecretsWhenFilesAreAbsent(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("GITEA_API_URL", "https://gitea.example.com")
	t.Setenv("SESSION_SECRET_FILE", "")
	t.Setenv("SESSION_SECRET", strings.Repeat("p", 32))
	t.Setenv("OAUTH_CLIENT_ID", "client-id")
	t.Setenv("OAUTH_CLIENT_SECRET_FILE", "")
	t.Setenv("OAUTH_CLIENT_SECRET", "legacy-oauth-secret")
	t.Setenv("LEGACY_WEBHOOK_SECRET_FILE", "")
	t.Setenv("WEBHOOK_SECRET", "legacy-webhook-secret")

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v, want legacy migration configuration to remain operable", err)
	}
	if got, want := string(config.SessionSecret), strings.Repeat("p", 32); got != want {
		t.Errorf("SessionSecret = %q, want %q", got, want)
	}
	if got, want := config.OAuthClientSecret, "legacy-oauth-secret"; got != want {
		t.Errorf("OAuthClientSecret = %q, want %q", got, want)
	}
	if got, want := config.WebhookSecret, "legacy-webhook-secret"; got != want {
		t.Errorf("WebhookSecret = %q, want %q", got, want)
	}
}

func TestLoadConfigSupportsLegacyDevelopmentComposeConfiguration(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("GITEA_API_URL", "http://gitea:3000")
	t.Setenv("SESSION_SECRET_FILE", "")
	t.Setenv("SESSION_SECRET", strings.Repeat("s", 32))
	t.Setenv("OAUTH_CLIENT_ID", "legacy-client")
	t.Setenv("OAUTH_CLIENT_SECRET_FILE", "")
	t.Setenv("OAUTH_CLIENT_SECRET", "legacy-oauth-secret")
	t.Setenv("LEGACY_WEBHOOK_SECRET_FILE", "")
	t.Setenv("WEBHOOK_SECRET", "legacy-webhook-secret")

	if _, err := LoadConfig(); err != nil {
		t.Fatalf("LoadConfig() error = %v, want explicitly configured legacy development Compose settings to start", err)
	}
}

func TestLoadConfigRejectsOAuthClientWithoutSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "production")
	t.Setenv("GITEA_API_URL", "https://gitea.example.com")
	t.Setenv("SESSION_SECRET_FILE", writeTestSecretFile(t, dir, "session", strings.Repeat("s", 32)))
	t.Setenv("OAUTH_CLIENT_ID", "client-id")
	t.Setenv("OAUTH_CLIENT_SECRET_FILE", "")
	t.Setenv("OAUTH_CLIENT_SECRET", "")

	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig must reject an OAuth client without a file or legacy OAuth secret")
	}
}

func TestLegacyMigrationDeliversWebhookAndRegistersUserAndOrganizationHooks(t *testing.T) {
	const secret = "legacy-webhook-secret"
	var registered []string
	gitea := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user/hooks":
			json.NewEncoder(w).Encode([]webhookInfo{})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user/orgs":
			json.NewEncoder(w).Encode([]map[string]string{{"username": "engineering"}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/orgs/engineering/hooks":
			json.NewEncoder(w).Encode([]webhookInfo{})
		case r.Method == http.MethodPost && (r.URL.Path == "/api/v1/user/hooks" || r.URL.Path == "/api/v1/orgs/engineering/hooks"):
			var payload struct {
				Config map[string]string `json:"config"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode webhook registration: %v", err)
				http.Error(w, "invalid webhook registration", http.StatusBadRequest)
				return
			}
			if got := payload.Config["secret"]; got != secret {
				t.Errorf("registered secret = %q, want %q", got, secret)
			}
			registered = append(registered, r.URL.Path)
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer gitea.Close()

	dir := t.TempDir()
	t.Setenv("APP_ENV", "development")
	t.Setenv("GITEA_API_URL", gitea.URL)
	t.Setenv("SESSION_SECRET_FILE", writeTestSecretFile(t, dir, "session", strings.Repeat("s", 32)))
	t.Setenv("LEGACY_WEBHOOK_SECRET_FILE", "")
	t.Setenv("WEBHOOK_SECRET", secret)

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	oauth := NewOAuthHandler(&OAuthConfig{APIURL: config.GiteaAPIURL}, nil, "http://deployer:8080/webhook", config.WebhookSecret)
	result := oauth.registerWebhooksWithResult(&UserToken{Username: "alice", AccessToken: "user-token"})
	if !result.Success {
		t.Fatalf("registerWebhooksWithResult() = %#v, want success", result)
	}
	if got, want := strings.Join(registered, ","), "/api/v1/user/hooks,/api/v1/orgs/engineering/hooks"; got != want {
		t.Errorf("registered hooks = %q, want %q", got, want)
	}

	body := `{"ref":"refs/heads/main","repository":{"name":"site","clone_url":"` + gitea.URL + `/alice/site.git","private":false}}`
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
	req.Header.Set("X-Gitea-Signature", computeSignature(body, secret))
	w := httptest.NewRecorder()
	NewDeployer(config).HandleWebhook(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("HandleWebhook() status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestReadSecretFileTrimsWhitespace(t *testing.T) {
	path := writeTestSecretFile(t, t.TempDir(), "secret", "\n secret-value \t\n")

	got, err := readSecretFile(path)
	if err != nil {
		t.Fatalf("readSecretFile() error = %v", err)
	}
	if want := "secret-value"; string(got) != want {
		t.Errorf("readSecretFile() = %q, want %q", got, want)
	}
}

func TestReadSecretFileRejectsEmptyFile(t *testing.T) {
	path := writeTestSecretFile(t, t.TempDir(), "secret", " \n\t")

	if _, err := readSecretFile(path); err == nil {
		t.Fatal("readSecretFile must reject an empty secret")
	}
}

func writeTestSecretFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write test secret %s: %v", name, err)
	}
	return path
}
