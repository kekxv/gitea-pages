package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestValidateSession tests session cookie validation
func TestValidateSession(t *testing.T) {
	secret := "test-secret-123"
	username := "testuser"

	tests := []struct {
		name     string
		cookie   *http.Cookie
		secret   string
		expected string
	}{
		{
			name:     "nil cookie",
			cookie:   nil,
			secret:   secret,
			expected: "",
		},
		{
			name:     "empty cookie value",
			cookie:   &http.Cookie{Name: sessionCookieName, Value: ""},
			secret:   secret,
			expected: "",
		},
		{
			name:     "empty secret",
			cookie:   &http.Cookie{Name: sessionCookieName, Value: "user:123:sig"},
			secret:   "",
			expected: "",
		},
		{
			name:     "invalid format - missing parts",
			cookie:   &http.Cookie{Name: sessionCookieName, Value: "user:123"},
			secret:   secret,
			expected: "",
		},
		{
			name:     "invalid format - too many parts",
			cookie:   &http.Cookie{Name: sessionCookieName, Value: "user:123:sig:extra"},
			secret:   secret,
			expected: "",
		},
		{
			name:     "invalid signature",
			cookie:   &http.Cookie{Name: sessionCookieName, Value: fmt.Sprintf("%s:%d:invalidsig", username, time.Now().Unix())},
			secret:   secret,
			expected: "",
		},
		{
			name:     "expired session",
			cookie:   &http.Cookie{Name: sessionCookieName, Value: createTestSessionValue(username, secret, time.Now().Add(-25*time.Hour).Unix())},
			secret:   secret,
			expected: "",
		},
		{
			name:     "valid session",
			cookie:   &http.Cookie{Name: sessionCookieName, Value: createTestSessionValue(username, secret, time.Now().Unix())},
			secret:   secret,
			expected: username,
		},
		{
			name:     "valid session - almost expired",
			cookie:   &http.Cookie{Name: sessionCookieName, Value: createTestSessionValue(username, secret, time.Now().Add(-23*time.Hour).Unix())},
			secret:   secret,
			expected: username,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateSession(tt.cookie, tt.secret)
			if result != tt.expected {
				t.Errorf("ValidateSession() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestSignSessionWithSecret tests session signing
func TestSignSessionWithSecret(t *testing.T) {
	tests := []struct {
		data     string
		secret   string
		expected string
	}{
		{"user:123", "secret", signSessionWithSecret("user:123", "secret")},
		{"", "secret", signSessionWithSecret("", "secret")},
		{"user:123", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.data, func(t *testing.T) {
			result := signSessionWithSecret(tt.data, tt.secret)
			if tt.secret != "" && result == "" {
				t.Errorf("signSessionWithSecret should return non-empty for valid secret")
			}
			if tt.secret == "" && result != "" {
				t.Errorf("signSessionWithSecret should return empty for empty secret")
			}
		})
	}
}

// TestSessionSignatureConsistency tests that signing is deterministic
func TestSessionSignatureConsistency(t *testing.T) {
	data := "testuser:123456789"
	secret := "my-secret"

	sig1 := signSessionWithSecret(data, secret)
	sig2 := signSessionWithSecret(data, secret)

	if sig1 != sig2 {
		t.Errorf("Signatures should be consistent: %s != %s", sig1, sig2)
	}

	// Different data should produce different signature
	sig3 := signSessionWithSecret("different:123456789", secret)
	if sig1 == sig3 {
		t.Errorf("Different data should produce different signatures")
	}

	// Different secret should produce different signature
	sig4 := signSessionWithSecret(data, "different-secret")
	if sig1 == sig4 {
		t.Errorf("Different secret should produce different signatures")
	}
}

// Helper function to create test session value
func createTestSessionValue(username, secret string, timestamp int64) string {
	data := fmt.Sprintf("%s:%d", username, timestamp)
	sig := signSessionWithSecret(data, secret)
	return fmt.Sprintf("%s:%s", data, sig)
}

// TestHandleWebhook_RequiresSecret tests that webhooks are rejected without secret
func TestHandleWebhook_RequiresSecret(t *testing.T) {
	config := &Config{
		Domain:        "example.com",
		WebhookSecret: "", // No secret configured
		PagesDir:      "/tmp/test-pages",
		MaxSiteSizeMB: 100,
		GiteaAPIURL:   "https://gitea.example.com",
	}
	deployer := NewDeployer(config)

	payload := `{"ref":"refs/heads/gh-pages","repository":{"name":"test","clone_url":"https://gitea.example.com/test/test.git","private":false}}`

	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	deployer.HandleWebhook(w, req)

	// Should be rejected because no secret configured
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d for no secret, got %d: %s", http.StatusServiceUnavailable, w.Code, w.Body.String())
	}
}

// TestHandleWebhook_PrivateRepoRequiresAPIURL tests that private repos require API URL
func TestHandleWebhook_PrivateRepoRequiresAPIURL(t *testing.T) {
	secret := "test-secret"
	body := `{"ref":"refs/heads/gh-pages","repository":{"name":"test","clone_url":"https://gitea.example.com/test/test.git","owner":{"username":"testuser"},"private":true}}`
	signature := computeSignature(body, secret)

	tests := []struct {
		name       string
		apiURL     string
		expected   int
	}{
		{
			name:     "no API URL - private repo rejected",
			apiURL:   "",
			expected: http.StatusForbidden,
		},
		{
			name:     "with API URL - would proceed (but clone fails in test)",
			apiURL:   "https://gitea.example.com",
			expected: http.StatusInternalServerError, // Clone fails without actual repo
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Domain:        "example.com",
				WebhookSecret: secret,
				PagesDir:      "/tmp/test-pages",
				MaxSiteSizeMB: 100,
				GiteaAPIURL:   tt.apiURL,
			}
			deployer := NewDeployer(config)

			req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
			req.Header.Set("X-Gitea-Signature", signature)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			deployer.HandleWebhook(w, req)

			if w.Code != tt.expected {
				t.Errorf("Expected status %d, got %d: %s", tt.expected, w.Code, w.Body.String())
			}
		})
	}
}

// TestHandleWebhook_UntrustedCloneURL tests rejection of untrusted clone URLs
func TestHandleWebhook_UntrustedCloneURL(t *testing.T) {
	secret := "test-secret"

	tests := []struct {
		name      string
		cloneURL  string
		apiURL    string
		expected  int
	}{
		{
			name:     "matching host - trusted",
			cloneURL: "https://gitea.example.com/user/repo.git",
			apiURL:   "https://gitea.example.com",
			expected: http.StatusInternalServerError, // Clone fails but URL is trusted
		},
		{
			name:     "different host - untrusted",
			cloneURL: "https://evil.com/user/repo.git",
			apiURL:   "https://gitea.example.com",
			expected: http.StatusForbidden,
		},
		{
			name:     "malicious URL with token phishing",
			cloneURL: "https://attacker.com/phishing.git",
			apiURL:   "https://gitea.example.com",
			expected: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"ref":"refs/heads/gh-pages","repository":{"name":"test","clone_url":"%s","owner":{"username":"testuser"},"private":false}}`, tt.cloneURL)
			signature := computeSignature(body, secret)

			config := &Config{
				Domain:        "example.com",
				WebhookSecret: secret,
				PagesDir:      "/tmp/test-pages",
				MaxSiteSizeMB: 100,
				GiteaAPIURL:   tt.apiURL,
			}
			deployer := NewDeployer(config)

			req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
			req.Header.Set("X-Gitea-Signature", signature)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			deployer.HandleWebhook(w, req)

			if w.Code != tt.expected {
				t.Errorf("Expected status %d, got %d: %s", tt.expected, w.Code, w.Body.String())
			}
		})
	}
}

// TestMaskUsername tests username masking for privacy
func TestMaskUsername(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"alice", "a****"},     // 5 chars -> 1 + 4 stars
		{"bob", "b**"},         // 3 chars -> 1 + 2 stars
		{"a", "a***"},          // 1 char -> 1 + 3 stars (special case)
		{"testuser", "t*******"}, // 8 chars -> 1 + 7 stars
		{"Caesar", "C*****"},   // 6 chars -> 1 + 5 stars
		{"123456", "1*****"},   // 6 chars -> 1 + 5 stars
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := maskUsername(tt.input)
			if result != tt.expected {
				t.Errorf("maskUsername(%s) = %s, expected %s", tt.input, result, tt.expected)
			}
		})
	}
}

// TestHandleStatus_NoAuth tests status page without authentication
func TestHandleStatus_NoAuth(t *testing.T) {
	webHandler := NewWebHandler(nil, nil, "example.com", "test-secret")

	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()

	webHandler.HandleStatus(w, req)

	// Should show login prompt
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "请先授权") {
		t.Errorf("Expected login prompt, got: %s", body)
	}
}

// TestHandleStatus_WithAuth tests status page with valid authentication
func TestHandleStatus_WithAuth(t *testing.T) {
	secret := "test-secret"
	username := "testuser"

	// Create token store with user
	tokenStore := NewTokenStore(t.TempDir())
	defer tokenStore.Close()

	tokenStore.Set(username, &UserToken{
		Username:    username,
		AccessToken: "test-token",
		CreatedAt:   time.Now(),
	})

	// Set registration result
	tokenStore.SetRegistrationResult(username, &WebhookRegistrationResult{
		Success: true,
		Message: "Webhook registered",
	})

	webHandler := NewWebHandler(nil, tokenStore, "example.com", secret)

	req := httptest.NewRequest("GET", "/status", nil)

	// Set valid session cookie
	sessionValue := createTestSessionValue(username, secret, time.Now().Unix())
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionValue,
	})

	w := httptest.NewRecorder()
	webHandler.HandleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()

	// Should show masked username
	masked := maskUsername(username)
	if !strings.Contains(body, masked) {
		t.Errorf("Expected masked username %s in response, got: %s", masked, body)
	}

	// Should show user's site URL
	if !strings.Contains(body, username+".example.com") {
		t.Errorf("Expected site URL for user, got: %s", body)
	}
}

// TestHandleStatus_InvalidSession tests status page with invalid session
func TestHandleStatus_InvalidSession(t *testing.T) {
	secret := "test-secret"

	webHandler := NewWebHandler(nil, nil, "example.com", secret)

	req := httptest.NewRequest("GET", "/status", nil)

	// Set invalid session cookie (wrong signature)
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: "testuser:123456789:invalidsignature",
	})

	w := httptest.NewRecorder()
	webHandler.HandleStatus(w, req)

	// Should show login prompt (invalid session)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "请先授权") {
		t.Errorf("Expected login prompt for invalid session, got: %s", body)
	}
}

// TestHandleStatus_ExpiredSession tests status page with expired session
func TestHandleStatus_ExpiredSession(t *testing.T) {
	secret := "test-secret"
	username := "testuser"

	webHandler := NewWebHandler(nil, nil, "example.com", secret)

	req := httptest.NewRequest("GET", "/status", nil)

	// Set expired session (25 hours ago, beyond 24h limit)
	sessionValue := createTestSessionValue(username, secret, time.Now().Add(-25*time.Hour).Unix())
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionValue,
	})

	w := httptest.NewRecorder()
	webHandler.HandleStatus(w, req)

	// Should show login prompt (expired session)
	body := w.Body.String()
	if !strings.Contains(body, "请先授权") {
		t.Errorf("Expected login prompt for expired session, got: %s", body)
	}
}