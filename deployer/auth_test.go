package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateSession(t *testing.T) {
	secret := "test-secret-123"
	username := "testuser"
	for _, tt := range []struct {
		name   string
		cookie *http.Cookie
		want   string
	}{
		{name: "nil cookie"},
		{name: "expired", cookie: &http.Cookie{Name: sessionCookieName, Value: createTestSessionValue(username, secret, time.Now().Add(-25*time.Hour).Unix())}},
		{name: "valid", cookie: &http.Cookie{Name: sessionCookieName, Value: createTestSessionValue(username, secret, time.Now().Unix())}, want: username},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateSession(tt.cookie, secret); got != tt.want {
				t.Fatalf("ValidateSession() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSessionSignatureConsistency(t *testing.T) {
	data := "testuser:123456789"
	if signSessionWithSecret(data, "secret") != signSessionWithSecret(data, "secret") {
		t.Fatal("session signing is not deterministic")
	}
	if signSessionWithSecret(data, "") != "" {
		t.Fatal("empty session secret was accepted")
	}
}

func createTestSessionValue(username, secret string, timestamp int64) string {
	data := fmt.Sprintf("%s:%d", username, timestamp)
	return fmt.Sprintf("%s:%s", data, signSessionWithSecret(data, secret))
}

func TestHandleStatusNoAuth(t *testing.T) {
	webHandler := NewWebHandler(nil, nil, "example.com", "test-secret")
	response := httptest.NewRecorder()
	webHandler.HandleStatus(response, httptest.NewRequest(http.MethodGet, "/status", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	for _, expected := range []string{"<style>", "class=\"container\"", "class=\"header\"", "class=\"btn btn-secondary\""} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("status page missing restored UI element %q", expected)
		}
	}
}
