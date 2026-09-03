package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/laibulle/robine-id/internal/adapters/accounts"
	"github.com/laibulle/robine-id/internal/adapters/blob"
	cryptoadapter "github.com/laibulle/robine-id/internal/adapters/crypto"
	"github.com/laibulle/robine-id/internal/adapters/keystore"
	"github.com/laibulle/robine-id/internal/adapters/memory"
	"github.com/laibulle/robine-id/internal/application"
	"github.com/laibulle/robine-id/internal/domain"
)

type webConfig struct {
	snapshot *domain.Snapshot
	err      error
}

func (w webConfig) Active(context.Context) (*domain.Snapshot, error) { return w.snapshot, w.err }

type webClock struct{ now time.Time }

func (w webClock) Now() time.Time { return w.now }

func newWebServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	hash, err := (cryptoadapter.Bcrypt{Cost: 4}).Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &domain.Snapshot{Fingerprint: "revision", Issuers: []domain.Issuer{{ID: "default", URL: "https://id.example/default", Scopes: []string{"openid", "profile", "email"}, TokenPolicy: domain.TokenPolicy{AuthorizationCodeLifetime: 60, IDTokenLifetime: 300, AccessTokenLifetime: 300, ClockSkew: 30}}}, Clients: []domain.Client{{ID: "public", Name: "Demo App", Type: "public", RedirectURIs: []string{"https://app.example/callback"}, PostLogoutRedirectURIs: []string{"https://app.example/signed-out"}, Scopes: []string{"openid", "profile", "email"}, GrantTypes: []string{"authorization_code"}, AuthenticationMethod: "none"}}, Users: []domain.User{{ID: "user", Identifier: "user@example.com", PasswordHash: hash, Name: "Ada", Email: "ada@example.com", Roles: []string{"admin"}}}, Claims: map[string]domain.ClaimMapping{"name": {Source: "name", Scope: "profile"}, "email": {Source: "email", Scope: "email"}}, Branding: domain.Branding{ProductName: "Robine ID", PrimaryColor: "#176b70"}, Authentication: domain.Authentication{Session: domain.SessionPolicy{IdleTimeout: 1800, AbsoluteTimeout: 28800, MaxConcurrent: 5}, RateLimit: domain.RateLimitPolicy{Attempts: 5, WindowSeconds: 60}}}
	stateRoot := t.TempDir()
	stateBlobs := blob.Local{Root: stateRoot}
	keys := &keystore.Encrypted{Blobs: stateBlobs, Key: "keys.enc", Secret: "012345678901234567890123456789012345678901234567890123456789"}
	provider := &application.Provider{Config: webConfig{snapshot: snapshot}, Accounts: &accounts.Blob{Blobs: stateBlobs, Key: "accounts.json"}, Codes: memory.NewAuthorizationCodes(), Tokens: memory.NewAccessTokens(), Sessions: memory.NewSessions(), Limits: memory.NewRateLimits(), Keys: keys, Passwords: cryptoadapter.Bcrypt{}, Clock: webClock{time.Unix(2_000_000_000, 0)}, Environment: func(string) string { return "" }}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := New(provider, logger, Options{SessionSecret: "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz", SecureCookies: false})
	if err != nil {
		t.Fatal(err)
	}
	testServer := httptest.NewServer(server.Handler())
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(testServer.Close)
	return testServer, client
}

func request(t *testing.T, client *http.Client, method, target string, form url.Values, headers map[string]string) *http.Response {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func body(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

var csrfPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func csrf(t *testing.T, html string) string {
	t.Helper()
	match := csrfPattern.FindStringSubmatch(html)
	if len(match) != 2 {
		t.Fatalf("csrf not found in %s", html)
	}
	return match[1]
}

func TestPublicPagesAndMiddleware(t *testing.T) {
	server, client := newWebServer(t)
	tests := []struct {
		path, contains string
		status         int
	}{{"/", "Identity infrastructure", 200}, {"/", "/assets/brand/robine-mark.png", 200}, {"/docs", "OIDC endpoints", 200}, {"/login", "account-login-form", 200}, {"/health/live", `"live"`, 200}, {"/health/ready", `"revision":"revision"`, 200}, {"/default/.well-known/openid-configuration", `"issuer":"https://id.example/default"`, 200}, {"/assets/app.css", "--primary", 200}, {"/assets/brand.css", ".brand-logo", 200}, {"/assets/brand/robine-mark.png", "\x89PNG", 200}, {"/favicon.ico", "\x89PNG", 200}, {"/assets/theme.css", "#176b70", 200}, {"/assets/htmx.min.js", "htmx", 200}}
	for _, test := range tests {
		response := request(t, client, "GET", server.URL+test.path, nil, nil)
		content := body(t, response)
		if response.StatusCode != test.status || !strings.Contains(content, test.contains) {
			t.Errorf("%s status=%d body=%s", test.path, response.StatusCode, content)
		}
		if response.Header.Get("x-request-id") == "" || response.Header.Get("X-Frame-Options") != "DENY" {
			t.Errorf("middleware missing for %s", test.path)
		}
	}
}

func TestDevelopmentContentSecurityPolicyAllowsReloadClient(t *testing.T) {
	server := &Server{devMode: true}
	recorder := httptest.NewRecorder()
	server.securityHeaders(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	policy := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "script-src 'self' 'unsafe-inline'") || !strings.Contains(policy, "worker-src 'self'") {
		t.Fatalf("development CSP does not allow the reload client: %s", policy)
	}
}

func TestCompleteHTMXAuthorizationFlow(t *testing.T) {
	server, client := newWebServer(t)
	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	authorization := url.Values{"client_id": {"public"}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid profile email"}, "nonce": {"nonce"}, "state": {"opaque-state"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
	response := request(t, client, "GET", server.URL+"/default/authorize?"+authorization.Encode(), nil, nil)
	loginHTML := body(t, response)
	if response.StatusCode != 200 || !strings.Contains(loginHTML, "account-login-form") {
		t.Fatalf("authorize: %d %s", response.StatusCode, loginHTML)
	}
	token := csrf(t, loginHTML)
	response = request(t, client, "POST", server.URL+"/login", url.Values{"csrf_token": {token}, "identifier": {"user@example.com"}, "password": {"password"}}, map[string]string{"HX-Request": "true"})
	consentHTML := body(t, response)
	if response.StatusCode != 200 || !strings.Contains(consentHTML, "Demo App") || strings.Contains(consentHTML, "<!doctype") {
		t.Fatalf("login: %d %s", response.StatusCode, consentHTML)
	}
	response = request(t, client, "POST", server.URL+"/default/authorize/consent", url.Values{"csrf_token": {token}, "decision": {"approve"}}, map[string]string{"HX-Request": "true"})
	_ = body(t, response)
	redirect := response.Header.Get("HX-Redirect")
	if response.StatusCode != 204 || redirect == "" {
		t.Fatalf("consent: %d %s", response.StatusCode, redirect)
	}
	callback, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if callback.Query().Get("state") != "opaque-state" || callback.Query().Get("code") == "" {
		t.Fatalf("callback %s", redirect)
	}
	response = request(t, client, "POST", server.URL+"/default/token", url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "client_id": {"public"}, "redirect_uri": {"https://app.example/callback"}, "code_verifier": {verifier}}, nil)
	tokenBody := body(t, response)
	if response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("token: %d %s", response.StatusCode, tokenBody)
	}
	var tokens map[string]any
	if err := json.Unmarshal([]byte(tokenBody), &tokens); err != nil {
		t.Fatal(err)
	}
	response = request(t, client, "GET", server.URL+"/default/userinfo", nil, map[string]string{"Authorization": "Bearer " + tokens["access_token"].(string)})
	info := body(t, response)
	if response.StatusCode != 200 || !strings.Contains(info, `"name":"Ada"`) {
		t.Fatalf("userinfo: %d %s", response.StatusCode, info)
	}
	response = request(t, client, "GET", server.URL+"/default/jwks.json", nil, nil)
	jwks := body(t, response)
	if response.StatusCode != 200 || strings.Contains(jwks, "private") || !strings.Contains(jwks, `"kid":"initial"`) {
		t.Fatalf("jwks: %d %s", response.StatusCode, jwks)
	}
	logoutQuery := url.Values{"id_token_hint": {tokens["id_token"].(string)}, "post_logout_redirect_uri": {"https://app.example/signed-out"}, "state": {"logout-state"}}
	response = request(t, client, "GET", server.URL+"/default/logout?"+logoutQuery.Encode(), nil, nil)
	logoutHTML := body(t, response)
	if response.StatusCode != 200 {
		t.Fatalf("logout page: %d %s", response.StatusCode, logoutHTML)
	}
	response = request(t, client, "POST", server.URL+"/default/logout", url.Values{"csrf_token": {csrf(t, logoutHTML)}}, nil)
	_ = body(t, response)
	if response.StatusCode != 303 || response.Header.Get("Location") != "https://app.example/signed-out?state=logout-state" {
		t.Fatalf("logout redirect: %d %s", response.StatusCode, response.Header.Get("Location"))
	}
}

func TestLoginAndProtocolFailures(t *testing.T) {
	server, client := newWebServer(t)
	response := request(t, client, "POST", server.URL+"/login", url.Values{"csrf_token": {"wrong"}, "identifier": {"user@example.com"}, "password": {"password"}}, nil)
	if response.StatusCode != 400 || !strings.Contains(body(t, response), "invalid CSRF") {
		t.Fatal("CSRF accepted")
	}
	login := request(t, client, "GET", server.URL+"/login", nil, nil)
	token := csrf(t, body(t, login))
	response = request(t, client, "POST", server.URL+"/login", url.Values{"csrf_token": {token}, "identifier": {"user@example.com"}, "password": {"wrong"}}, map[string]string{"HX-Request": "true"})
	if response.StatusCode != 401 || !strings.Contains(body(t, response), "incorrect") {
		t.Fatal("bad login response")
	}
	response = request(t, client, "GET", server.URL+"/default/authorize?client_id=missing", nil, nil)
	if response.StatusCode != 400 || !strings.Contains(body(t, response), "missing or invalid") {
		t.Fatal("bad authorization response")
	}
	response = request(t, client, "POST", server.URL+"/default/token", url.Values{"grant_type": {"authorization_code"}}, nil)
	if response.StatusCode != 401 || !strings.Contains(body(t, response), "invalid_client") {
		t.Fatal("bad token response")
	}
	response = request(t, client, "GET", server.URL+"/default/userinfo", nil, nil)
	if response.StatusCode != 401 || response.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("bearer accepted")
	}
	_ = body(t, response)
	response = request(t, client, "GET", server.URL+"/default/logout?post_logout_redirect_uri=https://evil.example/done", nil, nil)
	if response.StatusCode != 400 || !strings.Contains(body(t, response), "id_token_hint") {
		t.Fatal("unsafe logout redirect accepted")
	}
}

func TestConsentDenialAndLogout(t *testing.T) {
	server, client := newWebServer(t)
	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	authorization := url.Values{"client_id": {"public"}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "nonce": {"nonce"}, "state": {"state"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
	response := request(t, client, "GET", server.URL+"/default/authorize?"+authorization.Encode(), nil, nil)
	token := csrf(t, body(t, response))
	response = request(t, client, "POST", server.URL+"/login", url.Values{"csrf_token": {token}, "identifier": {"user@example.com"}, "password": {"password"}}, nil)
	_ = body(t, response)
	response = request(t, client, "POST", server.URL+"/default/authorize/consent", url.Values{"csrf_token": {token}, "decision": {"deny"}}, nil)
	if response.StatusCode != 303 || !strings.Contains(response.Header.Get("Location"), "access_denied") {
		t.Fatalf("denial %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	_ = body(t, response)
	response = request(t, client, "GET", server.URL+"/default/logout", nil, nil)
	logoutHTML := body(t, response)
	if response.StatusCode != 200 || !strings.Contains(logoutHTML, "logout-form") {
		t.Fatal("logout page")
	}
	logoutCSRF := csrf(t, logoutHTML)
	response = request(t, client, "POST", server.URL+"/default/logout", url.Values{"csrf_token": {logoutCSRF}}, map[string]string{"HX-Request": "true"})
	signedOut := body(t, response)
	if response.StatusCode != 200 || !strings.Contains(signedOut, "signed out") {
		t.Fatalf("logout %d %s", response.StatusCode, signedOut)
	}
}

func TestSessionCodecRejectsTamperingAndClears(t *testing.T) {
	codec, err := newSessionCodec("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSessionCodec("short", false); err == nil {
		t.Fatal("short secret accepted")
	}
	request := httptest.NewRequest("GET", "/", nil)
	fresh := codec.read(request)
	if fresh.CSRF == "" {
		t.Fatal("no csrf")
	}
	recorder := httptest.NewRecorder()
	if err := codec.write(recorder, fresh); err != nil {
		t.Fatal(err)
	}
	cookie := recorder.Result().Cookies()[0]
	if !cookie.Secure {
		t.Fatal("secure flag missing")
	}
	request.AddCookie(cookie)
	if got := codec.read(request); got.CSRF != fresh.CSRF {
		t.Fatal("round trip failed")
	}
	tampered := *cookie
	tampered.Value += "x"
	bad := httptest.NewRequest("GET", "/", nil)
	bad.AddCookie(&tampered)
	if got := codec.read(bad); got.CSRF == fresh.CSRF {
		t.Fatal("tampered cookie accepted")
	}
	clear := httptest.NewRecorder()
	codec.clear(clear)
	if clear.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("cookie not cleared")
	}
}

func TestAccountAndAdminPortal(t *testing.T) {
	server, client := newWebServer(t)
	response := request(t, client, "GET", server.URL+"/account", nil, nil)
	_ = body(t, response)
	if response.StatusCode != 303 || response.Header.Get("Location") != "/login" {
		t.Fatalf("anonymous account %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	response = request(t, client, "GET", server.URL+"/login", nil, nil)
	loginHTML := body(t, response)
	loginCSRF := csrf(t, loginHTML)
	response = request(t, client, "POST", server.URL+"/login", url.Values{"csrf_token": {loginCSRF}, "identifier": {"user@example.com"}, "password": {"password"}}, nil)
	_ = body(t, response)
	if response.StatusCode != 303 || response.Header.Get("Location") != "/account" {
		t.Fatalf("account return %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	response = request(t, client, "GET", server.URL+"/account", nil, nil)
	accountHTML := body(t, response)
	if response.StatusCode != 200 || !strings.Contains(accountHTML, "account-profile-form") {
		t.Fatalf("account %d %s", response.StatusCode, accountHTML)
	}
	accountCSRF := csrf(t, accountHTML)
	response = request(t, client, "POST", server.URL+"/account", url.Values{"csrf_token": {accountCSRF}, "name": {"Ada Updated"}, "email": {"updated@example.com"}}, map[string]string{"HX-Request": "true"})
	updated := body(t, response)
	if response.StatusCode != 200 || !strings.Contains(updated, "has been updated") || !strings.Contains(updated, "Ada Updated") {
		t.Fatalf("update %d %s", response.StatusCode, updated)
	}
	response = request(t, client, "GET", server.URL+"/admin", nil, nil)
	usersHTML := body(t, response)
	if response.StatusCode != 200 || !strings.Contains(usersHTML, "Configured users") || !strings.Contains(usersHTML, "Ada Updated") {
		t.Fatalf("admin %d %s", response.StatusCode, usersHTML)
	}
	response = request(t, client, "GET", server.URL+"/admin/users/user/edit", nil, nil)
	editHTML := body(t, response)
	if response.StatusCode != 200 || !strings.Contains(editHTML, "admin-user-form") {
		t.Fatalf("edit %d %s", response.StatusCode, editHTML)
	}
	response = request(t, client, "POST", server.URL+"/admin/users/user", url.Values{"csrf_token": {csrf(t, editHTML)}, "name": {"Ada Admin"}, "email": {"admin@example.com"}, "roles": {"admin, support"}, "enabled": {"true"}}, map[string]string{"HX-Request": "true"})
	adminHTML := body(t, response)
	if response.StatusCode != 200 || !strings.Contains(adminHTML, "Ada Admin") {
		t.Fatalf("admin update %d %s", response.StatusCode, adminHTML)
	}
	response = request(t, client, "POST", server.URL+"/admin/users/user", url.Values{"csrf_token": {accountCSRF}, "name": {""}, "email": {"bad"}, "roles": {"support"}}, map[string]string{"HX-Request": "true"})
	invalidAdmin := body(t, response)
	if response.StatusCode != 422 || !strings.Contains(invalidAdmin, "cannot remove") {
		t.Fatalf("invalid admin %d %s", response.StatusCode, invalidAdmin)
	}
	response = request(t, client, "POST", server.URL+"/account", url.Values{"csrf_token": {accountCSRF}, "name": {""}, "email": {"bad"}}, map[string]string{"HX-Request": "true"})
	if response.StatusCode != 422 || !strings.Contains(body(t, response), "valid email") {
		t.Fatal("invalid profile accepted")
	}
	response = request(t, client, "GET", server.URL+"/admin/users/missing/edit", nil, nil)
	if response.StatusCode != 404 {
		t.Fatalf("missing user %d", response.StatusCode)
	}
	_ = body(t, response)
}
