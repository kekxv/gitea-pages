package main

import (
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

func TestLoadConfigUsesFileBasedSecrets(t *testing.T) {
	dir := t.TempDir()
	sessionSecret := writeTestSecretFile(t, dir, "session", strings.Repeat("s", 32)+"\n")
	encryptionKey := writeTestSecretFile(t, dir, "key", strings.Repeat("k", 32)+"\n")

	t.Setenv("APP_ENV", "production")
	t.Setenv("GITEA_API_URL", "https://gitea.example.com")
	t.Setenv("SESSION_SECRET_FILE", sessionSecret)
	t.Setenv("TOKEN_ENCRYPTION_KEY_FILE", encryptionKey)
	t.Setenv("WEBHOOK_SECRET", "must-not-be-loaded")

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
	if config.WebhookSecret != "" {
		t.Errorf("WebhookSecret = %q, want empty: global webhook secrets are not loaded", config.WebhookSecret)
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
