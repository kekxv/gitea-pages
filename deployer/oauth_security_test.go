package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCreateHookCredentialGeneratesIndependentBase64URLCredentials(t *testing.T) {
	a, err := createHookCredential(HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"})
	if err != nil {
		t.Fatalf("create Alice credential: %v", err)
	}
	b, err := createHookCredential(HookPrincipal{Username: "bob", ScopeType: ScopeUser, ScopeName: "bob"})
	if err != nil {
		t.Fatalf("create Bob credential: %v", err)
	}
	if len(a.Key) != 32 || len(a.Secret) != 43 {
		t.Fatalf("credential lengths = key %d, secret %d; want a 32-byte stored key and 43-byte raw base64url secret", len(a.Key), len(a.Secret))
	}
	if a.Key == b.Key || bytes.Equal(a.Secret, b.Secret) {
		t.Fatal("independent hook credentials were reused")
	}
	if got, want := a.Principal(), (HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}); got != want {
		t.Errorf("credential principal = %#v, want %#v", got, want)
	}
}

func TestAuthorizeUsesConfiguredRedirectAndEncodedQuery(t *testing.T) {
	h := NewOAuthHandler(&OAuthConfig{
		ClientID:      "client id&value",
		RedirectURL:   "https://pages.example.com/oauth/callback?fixed=value",
		PublicAuthURL: "https://gitea.example.com/login/oauth/authorize",
	}, nil, "https://pages.example.com/webhook", "session-secret")
	req := httptest.NewRequest(http.MethodGet, "https://evil.example/oauth/authorize", nil)
	req.Host = "evil.example"
	w := httptest.NewRecorder()

	h.HandleAuthorize(w, req)

	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got, want := location.Scheme+"://"+location.Host+location.Path, "https://gitea.example.com/login/oauth/authorize"; got != want {
		t.Errorf("authorization endpoint = %q, want %q", got, want)
	}
	if got, want := location.Query().Get("redirect_uri"), "https://pages.example.com/oauth/callback?fixed=value"; got != want {
		t.Errorf("redirect_uri = %q, want %q", got, want)
	}
	if got, want := location.Query().Get("client_id"), "client id&value"; got != want {
		t.Errorf("client_id = %q, want %q", got, want)
	}
	if got, want := location.Query().Get("scope"), "read:user write:user read:repository write:organization"; got != want {
		t.Errorf("scope = %q, want %q", got, want)
	}
}

func TestOAuthConfigDisablesOrganizationScopeOnlyWhenConfigured(t *testing.T) {
	config := &Config{
		OAuthClientID:           "client",
		OAuthClientSecret:       "secret",
		OAuthRedirectURL:        "https://pages.example.com/oauth/callback",
		GiteaAPIURL:             "https://gitea.internal",
		GiteaPublicURL:          "https://gitea.example.com",
		EnableOrganizationHooks: false,
	}
	oauthConfig := oauthConfigFromAppConfig(config)
	if !oauthConfig.DisableOrganizationHooks {
		t.Fatal("explicitly disabled organization hooks still request organization scope")
	}
}

func TestRegistrationSkipsOrganizationEnumerationOnlyWhenDisabled(t *testing.T) {
	organizationCalls := 0
	gitea := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user/hooks":
			json.NewEncoder(w).Encode([]webhookInfo{})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/user/hooks":
			json.NewEncoder(w).Encode(webhookInfo{ID: 17})
		case r.URL.Path == "/api/v1/user/orgs":
			organizationCalls++
			http.Error(w, "organizations should not be requested", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer gitea.Close()
	store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	defer store.Close()
	h := NewOAuthHandler(&OAuthConfig{APIURL: gitea.URL, DisableOrganizationHooks: true}, store, "https://pages.example.com/webhook", "session-secret")
	result := h.registerWebhooksWithResult(&UserToken{Username: "alice", AccessToken: "alice-token"})
	if !result.Success {
		t.Fatalf("registration result = %#v, want user-hook success", result)
	}
	if organizationCalls != 0 {
		t.Errorf("organization API calls = %d, want 0", organizationCalls)
	}
}

func TestRegistrationDeletesNewGiteaHookWhenCredentialStorageFails(t *testing.T) {
	deleted := 0
	gitea := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user/hooks":
			json.NewEncoder(w).Encode([]webhookInfo{})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/user/hooks":
			json.NewEncoder(w).Encode(webhookInfo{ID: 42})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/user/hooks/42":
			deleted++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer gitea.Close()
	store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	h := NewOAuthHandler(&OAuthConfig{APIURL: gitea.URL}, store, "https://pages.example.com/webhook", "session-secret")
	if err := h.registerUserWebhook("alice-token", "alice"); err == nil {
		t.Fatal("registration succeeded despite unavailable credential storage")
	}
	if got, want := deleted, 1; got != want {
		t.Errorf("Gitea hook deletions = %d, want %d", got, want)
	}
}

func TestRegisterWebhooksCreatesAndStoresDistinctUserAndOrganizationCredentials(t *testing.T) {
	type registration struct {
		Path                string
		AuthorizationHeader string
		Secret              string
	}
	registrations := make([]registration, 0, 2)
	gitea := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user/hooks":
			json.NewEncoder(w).Encode([]webhookInfo{})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user/orgs":
			json.NewEncoder(w).Encode([]map[string]string{{"username": "platform"}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/orgs/platform/hooks":
			json.NewEncoder(w).Encode([]webhookInfo{})
		case r.Method == http.MethodPost:
			var payload struct {
				Config              map[string]string `json:"config"`
				AuthorizationHeader string            `json:"authorization_header"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode registration: %v", err)
			}
			registrations = append(registrations, registration{r.URL.Path, payload.AuthorizationHeader, payload.Config["secret"]})
			json.NewEncoder(w).Encode(webhookInfo{ID: int64(100 + len(registrations))})
		default:
			http.NotFound(w, r)
		}
	}))
	defer gitea.Close()

	store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	defer store.Close()
	h := NewOAuthHandler(&OAuthConfig{APIURL: gitea.URL}, store, "https://pages.example.com/webhook", "session-secret")
	result := h.registerWebhooksWithResult(&UserToken{Username: "alice", AccessToken: "alice-token"})
	if !result.Success {
		t.Fatalf("registration result = %#v, want success", result)
	}
	if len(registrations) != 2 {
		t.Fatalf("registrations = %d, want user and organization hooks", len(registrations))
	}

	for _, registered := range registrations {
		const prefix = "Gitea-Pages "
		if len(registered.AuthorizationHeader) <= len(prefix) || registered.AuthorizationHeader[:len(prefix)] != prefix {
			t.Fatalf("Authorization header = %q, want Gitea-Pages key", registered.AuthorizationHeader)
		}
		key, err := base64.RawURLEncoding.DecodeString(registered.AuthorizationHeader[len(prefix):])
		if err != nil {
			t.Fatalf("decode registered key: %v", err)
		}
		credential, err := store.GetHook(context.Background(), string(key))
		if err != nil {
			t.Fatalf("load stored credential: %v", err)
		}
		if credential == nil {
			t.Fatalf("no stored credential for registered key %q", registered.AuthorizationHeader)
		}
		if got, want := string(credential.Secret), registered.Secret; got != want {
			t.Errorf("stored secret = %q, want Gitea payload secret %q", got, want)
		}
	}
	if registrations[0].AuthorizationHeader == registrations[1].AuthorizationHeader || registrations[0].Secret == registrations[1].Secret {
		t.Fatal("user and organization hooks must not share credentials")
	}
}

func TestRegisteredHookAuthenticatesSignedDelivery(t *testing.T) {
	var authorizationHeader, secret string
	gitea := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user/hooks":
			json.NewEncoder(w).Encode([]webhookInfo{})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/user/hooks":
			var payload struct {
				Config              map[string]string `json:"config"`
				AuthorizationHeader string            `json:"authorization_header"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode registration: %v", err)
			}
			authorizationHeader = payload.AuthorizationHeader
			secret = payload.Config["secret"]
			json.NewEncoder(w).Encode(webhookInfo{ID: 91})
		default:
			http.NotFound(w, r)
		}
	}))
	defer gitea.Close()

	store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	defer store.Close()
	h := NewOAuthHandler(&OAuthConfig{APIURL: gitea.URL, DisableOrganizationHooks: true}, store, "https://pages.example.com/webhook", "session-secret")
	if err := h.registerUserWebhook("alice-token", "alice"); err != nil {
		t.Fatalf("register user hook: %v", err)
	}
	const prefix = "Gitea-Pages "
	if !strings.HasPrefix(authorizationHeader, prefix) {
		t.Fatalf("authorization header = %q, want %q prefix", authorizationHeader, prefix)
	}
	body := []byte(`{"repository":{"id":42}}`)
	request := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	request.Header.Set("Authorization", authorizationHeader)
	request.Header.Set("X-Gitea-Delivery", "registered-delivery")
	request.Header.Set("X-Gitea-Signature", computeSignature(string(body), secret))

	authenticated, err := AuthenticateWebhook(context.Background(), request, store)
	if err != nil {
		t.Fatalf("AuthenticateWebhook registered delivery: %v", err)
	}
	if got, want := authenticated.Principal, (HookPrincipal{Username: "alice", ScopeType: ScopeUser, ScopeName: "alice"}); got != want {
		t.Errorf("authenticated principal = %#v, want %#v", got, want)
	}
}

func TestOrganizationRegistrationPreservesAuthorizedAdministratorPool(t *testing.T) {
	var hooks []webhookInfo
	created := 0
	gitea := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/orgs/platform/hooks":
			json.NewEncoder(w).Encode(hooks)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/orgs/platform/hooks":
			var payload webhookInfo
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode hook: %v", err)
			}
			payload.ID = 61
			hooks = []webhookInfo{payload}
			created++
			json.NewEncoder(w).Encode(payload)
		case r.Method == http.MethodPatch:
			t.Fatal("a later organization authorizer must not replace the existing hook")
		default:
			http.NotFound(w, r)
		}
	}))
	defer gitea.Close()

	store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	defer store.Close()
	h := NewOAuthHandler(&OAuthConfig{APIURL: gitea.URL}, store, "https://pages.example.com/webhook", "session-secret")
	if err := h.registerOrgWebhook("alice-token", "platform", "alice"); err != nil {
		t.Fatalf("register Alice: %v", err)
	}
	if err := h.registerOrgWebhook("bob-token", "platform", "bob"); err != nil {
		t.Fatalf("register Bob: %v", err)
	}
	if got, want := created, 1; got != want {
		t.Errorf("organization hook creations = %d, want %d", got, want)
	}
	admins, err := store.OrganizationHookAuthorizers(context.Background(), "platform")
	if err != nil {
		t.Fatalf("load organization authorizers: %v", err)
	}
	if got, want := len(admins), 2; got != want {
		t.Fatalf("administrator pool length = %d, want %d (%#v)", got, want, admins)
	}
	if admins[0] != "alice" || admins[1] != "bob" {
		t.Errorf("administrator pool = %#v, want Alice and Bob", admins)
	}
}

func TestValidateSessionRejectsTimestampMoreThanOneMinuteInFuture(t *testing.T) {
	secret := "session-secret"
	cookie := &http.Cookie{
		Name:  sessionCookieName,
		Value: createTestSessionValue("alice", secret, time.Now().Add(61*time.Second).Unix()),
	}
	if got := ValidateSession(cookie, secret); got != "" {
		t.Errorf("future session validated for %q, want rejection", got)
	}
}

func TestExchangeCodeUsesEncodedFormAndConfiguredRedirect(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse token form: %v", err)
		}
		if got, want := r.Form.Get("client_id"), "client id&value"; got != want {
			t.Errorf("client_id = %q, want %q", got, want)
		}
		if got, want := r.Form.Get("client_secret"), "secret & value"; got != want {
			t.Errorf("client_secret = %q, want %q", got, want)
		}
		if got, want := r.Form.Get("redirect_uri"), "https://pages.example.com/oauth/callback?fixed=value"; got != want {
			t.Errorf("redirect_uri = %q, want %q", got, want)
		}
		if got, want := r.Form.Get("code"), "code & value"; got != want {
			t.Errorf("code = %q, want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"access"}`))
	}))
	defer tokenServer.Close()
	h := NewOAuthHandler(&OAuthConfig{
		ClientID:     "client id&value",
		ClientSecret: "secret & value",
		TokenURL:     tokenServer.URL,
	}, nil, "https://pages.example.com/webhook", "session-secret")
	if _, err := h.exchangeCode("code & value", "https://pages.example.com/oauth/callback?fixed=value"); err != nil {
		t.Fatalf("exchangeCode: %v", err)
	}
}

func TestOAuthTokenExchangeRejectsRedirectBeforeClientSecretDisclosure(t *testing.T) {
	targetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalled = true
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse redirected token form: %v", err)
		}
		if secret := r.Form.Get("client_secret"); secret != "" {
			t.Errorf("redirect target received client_secret %q", secret)
		}
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "redirected-token"})
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	handler := NewOAuthHandler(&OAuthConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		TokenURL:     redirector.URL + "/login/oauth/access_token",
	}, nil, "https://pages.example.com/webhook", "session-secret")
	if _, err := handler.exchangeCode("authorization-code", "https://pages.example.com/oauth/callback"); err == nil {
		t.Fatal("exchangeCode followed a token endpoint redirect")
	}
	if targetCalled {
		t.Fatal("OAuth client-secret redirect target was contacted")
	}
}

func TestRefreshAccessTokenUsesEncodedForm(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse refresh form: %v", err)
		}
		if got, want := r.Form.Get("client_secret"), "secret & value"; got != want {
			t.Errorf("client_secret = %q, want %q", got, want)
		}
		if got, want := r.Form.Get("refresh_token"), "refresh & value"; got != want {
			t.Errorf("refresh_token = %q, want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"access"}`))
	}))
	defer tokenServer.Close()
	h := NewOAuthHandler(&OAuthConfig{ClientID: "client & value", ClientSecret: "secret & value", TokenURL: tokenServer.URL}, nil, "https://pages.example.com/webhook", "session-secret")
	if _, err := h.refreshAccessToken("refresh & value"); err != nil {
		t.Fatalf("refreshAccessToken: %v", err)
	}
}

func TestCallbackConsumesOAuthStateCookie(t *testing.T) {
	gitea := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"access"}`))
		case "/api/v1/user":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"login":"<alice>"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer gitea.Close()
	store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	defer store.Close()
	h := NewOAuthHandler(&OAuthConfig{
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURL:  "https://pages.example.com/oauth/callback",
		TokenURL:     gitea.URL + "/token",
		APIURL:       gitea.URL,
	}, store, "https://pages.example.com/webhook", "session-secret")
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?state=valid-state&code=code", nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "valid-state"})
	w := httptest.NewRecorder()

	h.HandleCallback(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("callback status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "<******") || !strings.Contains(w.Body.String(), "&lt;******") {
		t.Errorf("callback success page did not escape masked username: %s", w.Body.String())
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "oauth_state" {
			if cookie.MaxAge >= 0 {
				t.Errorf("state cookie MaxAge = %d, want deletion", cookie.MaxAge)
			}
			return
		}
	}
	t.Error("callback did not delete oauth_state cookie")
}

func TestStatusEscapesUsernameDomainAndRegistrationError(t *testing.T) {
	secret := "session-secret"
	username := "<alice>"
	store, err := NewTokenStore(t.TempDir(), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	defer store.Close()
	store.SetRegistrationResult(username, &WebhookRegistrationResult{Message: "<registration error>", Success: false})
	h := NewWebHandler(nil, store, "<pages.example.com>", secret)
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: createTestSessionValue(username, secret, time.Now().Unix())})
	w := httptest.NewRecorder()

	h.HandleStatus(w, req)

	body := w.Body.String()
	for _, unescaped := range []string{"<alice>", "<pages.example.com>", "<registration error>"} {
		if bytes.Contains([]byte(body), []byte(unescaped)) {
			t.Errorf("status page contains unescaped value %q", unescaped)
		}
	}
	for _, escaped := range []string{"&lt;pages.example.com&gt;", "&lt;registration error&gt;"} {
		if !bytes.Contains([]byte(body), []byte(escaped)) {
			t.Errorf("status page missing escaped value %q: %s", escaped, body)
		}
	}
}
