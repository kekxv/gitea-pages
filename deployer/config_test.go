package main

import (
	"bytes"
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

func TestLoadConfigRejectsMissingTokenEncryptionKey(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("GITEA_API_URL", "https://gitea.example.com")
	t.Setenv("SESSION_SECRET_FILE", "")
	t.Setenv("SESSION_SECRET", strings.Repeat("s", 32))
	t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", "")
	t.Setenv("OAUTH_CLIENT_ID", "")
	t.Setenv("OAUTH_CLIENT_SECRET_FILE", "")
	t.Setenv("OAUTH_CLIENT_SECRET", "")
	t.Setenv("LEGACY_WEBHOOK_SECRET_FILE", "")
	t.Setenv("WEBHOOK_SECRET", "")

	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig must reject a valid configuration with no token encryption key")
	}
}

func TestLoadConfigDoesNotUseLegacyWebhookSecretsAtRuntime(t *testing.T) {
	dir := t.TempDir()
	sessionSecret := writeTestSecretFile(t, dir, "session", strings.Repeat("s", 32)+"\n")
	encryptionKey := writeTestSecretFile(t, dir, "key", strings.Repeat("k", 32))
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
}

func TestLoadConfigPreservesRawTokenEncryptionKeyWhitespaceBytes(t *testing.T) {
	dir := t.TempDir()
	key := []byte("\n" + strings.Repeat("k", 30) + "\t")

	t.Setenv("APP_ENV", "production")
	t.Setenv("GITEA_API_URL", "https://gitea.example.com")
	t.Setenv("SESSION_SECRET_FILE", writeTestSecretFile(t, dir, "session", strings.Repeat("s", 32)))
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", keyPath)

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v, want a 32-byte raw key to be accepted", err)
	}
	if !bytes.Equal(config.TokenEncryptionKey, key) {
		t.Fatalf("TokenEncryptionKey = %x, want raw key %x", config.TokenEncryptionKey, key)
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

func TestLoadConfigRejectsHTTPPublicURLsInProduction(t *testing.T) {
	for _, variable := range []string{"OAUTH_REDIRECT_URL", "WEBHOOK_PUBLIC_URL"} {
		t.Run(variable, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("APP_ENV", "production")
			t.Setenv("GITEA_API_URL", "https://gitea.example.com")
			t.Setenv("SESSION_SECRET_FILE", writeTestSecretFile(t, dir, "session", strings.Repeat("s", 32)))
			t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", writeTestSecretFile(t, dir, "key", strings.Repeat("k", 32)))
			t.Setenv("OAUTH_REDIRECT_URL", "")
			t.Setenv("WEBHOOK_PUBLIC_URL", "")
			t.Setenv(variable, "http://localhost:8080/path")

			if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), variable+" must use HTTPS outside local development") {
				t.Fatalf("LoadConfig() error = %v, want production HTTP rejection for %s", err, variable)
			}
		})
	}
}

func TestLoadConfigAllowsHTTPPublicURLsOnlyOnExactDevelopmentHosts(t *testing.T) {
	for _, host := range []string{"localhost:8080", "127.0.0.1:8080", "[::1]:8080", "deployer:8080"} {
		t.Run("allow_"+host, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("APP_ENV", "development")
			t.Setenv("GITEA_API_URL", "http://gitea:3000")
			t.Setenv("SESSION_SECRET_FILE", writeTestSecretFile(t, dir, "session", strings.Repeat("s", 32)))
			t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", writeTestSecretFile(t, dir, "key", strings.Repeat("k", 32)))
			t.Setenv("OAUTH_REDIRECT_URL", "http://"+host+"/oauth/callback")
			t.Setenv("WEBHOOK_PUBLIC_URL", "http://"+host+"/webhook")

			if _, err := LoadConfig(); err != nil {
				t.Fatalf("LoadConfig() error = %v, want exact development host %s accepted", err, host)
			}
		})
	}
	for _, host := range []string{"127.0.0.2:8080", "pages.localhost:8080", "deployer.example:8080"} {
		t.Run("reject_"+host, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("APP_ENV", "development")
			t.Setenv("GITEA_API_URL", "http://gitea:3000")
			t.Setenv("SESSION_SECRET_FILE", writeTestSecretFile(t, dir, "session", strings.Repeat("s", 32)))
			t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", writeTestSecretFile(t, dir, "key", strings.Repeat("k", 32)))
			t.Setenv("OAUTH_REDIRECT_URL", "http://"+host+"/oauth/callback")
			t.Setenv("WEBHOOK_PUBLIC_URL", "https://pages.example.com/webhook")

			if _, err := LoadConfig(); err == nil {
				t.Fatalf("LoadConfig accepted disallowed development host %s", host)
			}
		})
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
	dir := t.TempDir()
	t.Setenv("APP_ENV", "production")
	t.Setenv("GITEA_API_URL", "https://gitea.example.com")
	t.Setenv("SESSION_SECRET_FILE", "")
	t.Setenv("SESSION_SECRET", strings.Repeat("p", 32))
	t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", writeTestSecretFile(t, dir, "key", strings.Repeat("k", 32)))
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
}

func TestLoadConfigSupportsLegacyDevelopmentComposeConfiguration(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_ENV", "development")
	t.Setenv("GITEA_API_URL", "http://gitea:3000")
	t.Setenv("SESSION_SECRET_FILE", "")
	t.Setenv("SESSION_SECRET", strings.Repeat("s", 32))
	t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", writeTestSecretFile(t, dir, "key", strings.Repeat("k", 32)))
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
	t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", writeTestSecretFile(t, dir, "key", strings.Repeat("k", 32)))
	t.Setenv("OAUTH_CLIENT_ID", "client-id")
	t.Setenv("OAUTH_CLIENT_SECRET_FILE", "")
	t.Setenv("OAUTH_CLIENT_SECRET", "")

	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig must reject an OAuth client without a file or legacy OAuth secret")
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
