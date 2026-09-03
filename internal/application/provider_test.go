package application

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	cryptoadapter "github.com/laibulle/robine-id/internal/adapters/crypto"
	"github.com/laibulle/robine-id/internal/adapters/memory"
	"github.com/laibulle/robine-id/internal/domain"
)

type staticConfig struct {
	snapshot *domain.Snapshot
	err      error
}

func (s staticConfig) Active(context.Context) (*domain.Snapshot, error) { return s.snapshot, s.err }

type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }

type testKeys struct {
	keys map[string][]domain.SigningKey
}

type testAccounts struct{ users map[string]domain.User }

func (a *testAccounts) Get(_ context.Context, id string) (domain.User, error) {
	user, ok := a.users[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return user, nil
}
func (a *testAccounts) Save(_ context.Context, user domain.User) error {
	a.users[user.ID] = user
	return nil
}

func (k *testKeys) Active(_ context.Context, issuer string) (domain.SigningKey, error) {
	for _, key := range k.keys[issuer] {
		if key.Active {
			return key, nil
		}
	}
	return domain.SigningKey{}, domain.ErrNotFound
}
func (k *testKeys) All(_ context.Context, issuer string) ([]domain.SigningKey, error) {
	return k.keys[issuer], nil
}
func (k *testKeys) Rotate(_ context.Context, issuer, id string) (domain.SigningKey, error) {
	private, _ := rsa.GenerateKey(rand.Reader, 1024)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)})
	key := domain.SigningKey{ID: id, PrivatePEM: encoded, Active: true}
	for i := range k.keys[issuer] {
		k.keys[issuer][i].Active = false
	}
	k.keys[issuer] = append(k.keys[issuer], key)
	return key, nil
}

func testSnapshot(hash string) *domain.Snapshot {
	no := false
	return &domain.Snapshot{SchemaVersion: 1, Fingerprint: "fingerprint", Issuers: []domain.Issuer{{ID: "default", URL: "https://id.example/default", Scopes: []string{"openid", "profile", "email"}, TokenPolicy: domain.TokenPolicy{AuthorizationCodeLifetime: 60, IDTokenLifetime: 300, AccessTokenLifetime: 600, ClockSkew: 30}}}, Clients: []domain.Client{
		{ID: "public", Name: "Public App", Type: "public", RedirectURIs: []string{"https://app.example/callback"}, Scopes: []string{"openid", "profile", "email"}, GrantTypes: []string{"authorization_code"}, AuthenticationMethod: "none"},
		{ID: "confidential", Name: "Private App", Type: "confidential", RedirectURIs: []string{"https://private.example/callback"}, Scopes: []string{"openid"}, GrantTypes: []string{"authorization_code"}, AuthenticationMethod: "client_secret_post", PKCERequired: &no, NonceRequired: &no, SecretReference: domain.SecretReference{Key: "CLIENT_SECRET"}},
	}, Users: []domain.User{{ID: "user", Identifier: "user@example.com", PasswordHash: hash, Name: "Ada Lovelace", Email: "ada@example.com", Roles: []string{"admin"}, Claims: map[string]any{"given_name": "Ada"}}}, Claims: map[string]domain.ClaimMapping{"name": {Source: "name", Scope: "profile"}, "given_name": {Source: "given_name", Scope: "profile"}, "email": {Source: "email", Scope: "email"}}, Branding: domain.Branding{ProductName: "Robine ID", Locales: []string{"en", "fr"}}, Authentication: domain.Authentication{Session: domain.SessionPolicy{IdleTimeout: 1800, AbsoluteTimeout: 28800, MaxConcurrent: 5}, RateLimit: domain.RateLimitPolicy{Attempts: 5, WindowSeconds: 60}}}
}

func newTestProvider(t *testing.T) (*Provider, *domain.Snapshot) {
	t.Helper()
	hasher := cryptoadapter.Bcrypt{Cost: 4}
	hash, err := hasher.Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot(hash)
	provider := &Provider{Config: staticConfig{snapshot: snapshot}, Codes: memory.NewAuthorizationCodes(), Tokens: memory.NewAccessTokens(), Sessions: memory.NewSessions(), Limits: memory.NewRateLimits(), Keys: &testKeys{keys: map[string][]domain.SigningKey{}}, Passwords: hasher, Clock: fixedClock{time.Unix(2_000_000_000, 0)}, Environment: func(key string) string {
		if key == "CLIENT_SECRET" {
			return "secret"
		}
		return ""
	}}
	provider.Accounts = &testAccounts{users: map[string]domain.User{}}
	return provider, snapshot
}

func TestAccountManagement(t *testing.T) {
	p, _ := newTestProvider(t)
	ctx := context.Background()
	updated, err := p.UpdateProfile(ctx, "user", ProfileUpdate{Name: "Ada Byron", Email: "byron@example.com", CurrentPassword: "password", NewPassword: "new-password-123", PasswordConfirmation: "new-password-123"})
	if err != nil || updated.Name != "Ada Byron" {
		t.Fatalf("profile %#v %v", updated, err)
	}
	if !p.Passwords.Compare(updated.PasswordHash, "new-password-123") {
		t.Fatal("password not changed")
	}
	if _, err := p.UpdateProfile(ctx, "user", ProfileUpdate{Name: "", Email: "invalid", NewPassword: "short", PasswordConfirmation: "different", CurrentPassword: "wrong"}); err == nil {
		t.Fatal("invalid profile accepted")
	}
	users, err := p.ListUsers(ctx)
	if err != nil || len(users) != 1 || users[0].Name != "Ada Byron" {
		t.Fatalf("users %#v %v", users, err)
	}
	managed, err := p.UpdateUserAsAdmin(ctx, "user", "user", AdminUpdate{Name: "Administrator", Email: "admin@example.com", Roles: "admin, support", Enabled: true})
	if err != nil || !Admin(managed) || len(managed.Roles) != 2 {
		t.Fatalf("admin %#v %v", managed, err)
	}
	if _, err := p.UpdateUserAsAdmin(ctx, "user", "user", AdminUpdate{Name: "Administrator", Email: "admin@example.com", Roles: "support", Enabled: false}); err == nil {
		t.Fatal("self lockout accepted")
	}
	if _, err := p.UpdateUserAsAdmin(ctx, "user", "user", AdminUpdate{Name: "Administrator", Email: "bad", Roles: "admin, ADMIN", Enabled: true}); err == nil {
		t.Fatal("invalid admin update accepted")
	}
}

func validAuthorization() url.Values {
	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	return url.Values{"client_id": {"public"}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid profile email"}, "nonce": {"nonce"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "state": {"state"}, "ui_locales": {"fr en"}}
}

func TestDiscovery(t *testing.T) {
	p, _ := newTestProvider(t)
	metadata, err := p.Discovery(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	if metadata["issuer"] != "https://id.example/default" || metadata["authorization_endpoint"] != "https://id.example/default/authorize" {
		t.Fatalf("metadata %#v", metadata)
	}
	if _, err := p.Discovery(context.Background(), "unknown"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestValidateAuthorization(t *testing.T) {
	p, _ := newTestProvider(t)
	request, err := p.ValidateAuthorization(context.Background(), "default", validAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	if request.ClientID != "public" || request.Locale != "fr" || len(request.Scopes) != 3 {
		t.Fatalf("request %#v", request)
	}
	tests := []struct {
		name   string
		mutate func(url.Values)
	}{
		{"missing", func(v url.Values) { v.Del("client_id") }},
		{"response", func(v url.Values) { v.Set("response_type", "token") }},
		{"issuer", func(v url.Values) {}},
		{"client", func(v url.Values) { v.Set("client_id", "missing") }},
		{"redirect", func(v url.Values) { v.Set("redirect_uri", "https://evil.example") }},
		{"openid", func(v url.Values) { v.Set("scope", "profile") }},
		{"scope", func(v url.Values) { v.Set("scope", "openid unknown") }},
		{"duplicate scope", func(v url.Values) { v.Set("scope", "openid openid") }},
		{"nonce", func(v url.Values) { v.Del("nonce") }},
		{"pkce method", func(v url.Values) { v.Set("code_challenge_method", "plain") }},
		{"pkce characters", func(v url.Values) { v.Set("code_challenge", strings.Repeat("!", 43)) }},
		{"prompt", func(v url.Values) { v.Set("prompt", "invalid") }},
		{"prompt none", func(v url.Values) { v.Set("prompt", "none login") }},
		{"max age", func(v url.Values) { v.Set("max_age", "-1") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := validAuthorization()
			test.mutate(values)
			issuer := "default"
			if test.name == "issuer" {
				issuer = "missing"
			}
			if _, err := p.ValidateAuthorization(context.Background(), issuer, values); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	values := url.Values{"client_id": {"confidential"}, "redirect_uri": {"https://private.example/callback"}, "response_type": {"code"}, "scope": {"openid"}}
	if _, err := p.ValidateAuthorization(context.Background(), "default", values); err != nil {
		t.Fatalf("confidential exception rejected: %v", err)
	}
}

func TestAuthenticationAndSessions(t *testing.T) {
	p, snapshot := newTestProvider(t)
	ctx := context.Background()
	user, retry, err := p.Authenticate(ctx, " USER@example.com ", "password", "127.0.0.1")
	if err != nil || retry != 0 || user.ID != "user" {
		t.Fatalf("auth %#v %v %v", user, retry, err)
	}
	if _, _, err := p.Authenticate(ctx, "missing@example.com", "password", "127.0.0.2"); err == nil {
		t.Fatal("unknown accepted")
	}
	if _, _, err := p.Authenticate(ctx, "user@example.com", "wrong", "127.0.0.3"); err == nil {
		t.Fatal("wrong accepted")
	}
	snapshot.Authentication.RateLimit.Attempts = 1
	if _, _, err := p.Authenticate(ctx, "user@example.com", "wrong", "limited"); err == nil {
		t.Fatal("first wrong accepted")
	}
	if _, retry, err := p.Authenticate(ctx, "user@example.com", "wrong", "limited"); err == nil || retry == 0 {
		t.Fatal("rate limit missing")
	}
	session, err := p.StartSession(ctx, "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ValidateSession(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.EndSession(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ValidateSession(ctx, session.ID); err == nil {
		t.Fatal("ended valid")
	}
}

func TestClientAuthentication(t *testing.T) {
	p, _ := newTestProvider(t)
	ctx := context.Background()
	if _, err := p.AuthenticateClient(ctx, "public", "none", ""); err != nil {
		t.Fatal(err)
	}
	for _, input := range [][3]string{{"missing", "none", ""}, {"public", "client_secret_post", "x"}, {"confidential", "none", ""}, {"confidential", "client_secret_post", "wrong"}} {
		if _, err := p.AuthenticateClient(ctx, input[0], input[1], input[2]); err == nil {
			t.Errorf("accepted %#v", input)
		}
	}
	if client, err := p.AuthenticateClient(ctx, "confidential", "client_secret_post", "secret"); err != nil || client.ID != "confidential" {
		t.Fatal(err)
	}
}

func TestAuthorizationCodeTokenAndUserInfo(t *testing.T) {
	p, _ := newTestProvider(t)
	ctx := context.Background()
	values := validAuthorization()
	request, err := p.ValidateAuthorization(ctx, "default", values)
	if err != nil {
		t.Fatal(err)
	}
	code, err := p.IssueAuthorizationCode(ctx, request, "user", time.Unix(1_999_999_900, 0))
	if err != nil {
		t.Fatal(err)
	}
	client, _ := p.AuthenticateClient(ctx, "public", "none", "")
	tokenValues := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"public"}, "redirect_uri": {"https://app.example/callback"}, "code_verifier": {strings.Repeat("v", 43)}}
	response, err := p.ExchangeCode(ctx, "default", tokenValues, client)
	if err != nil {
		t.Fatal(err)
	}
	if response.TokenType != "Bearer" || response.ExpiresIn != 600 || len(strings.Split(response.IDToken, ".")) != 3 {
		t.Fatalf("response %#v", response)
	}
	claims := verifyToken(t, p, response.IDToken)
	if claims["sub"] != "user" || claims["nonce"] != "nonce" {
		t.Fatalf("claims %#v", claims)
	}
	verified, err := p.VerifyIDToken(ctx, "default", response.IDToken)
	if err != nil || verified["aud"] != "public" {
		t.Fatalf("verify %#v %v", verified, err)
	}
	if _, err := p.VerifyIDToken(ctx, "default", response.IDToken+"x"); err == nil {
		t.Fatal("forged token accepted")
	}
	info, err := p.UserInfo(ctx, "default", response.AccessToken)
	if err != nil || info["name"] != "Ada Lovelace" || info["email"] != "ada@example.com" {
		t.Fatalf("userinfo %#v %v", info, err)
	}
	keys, err := p.JWKS(ctx, "default")
	if err != nil || len(keys["keys"].([]map[string]any)) != 1 {
		t.Fatalf("jwks %#v %v", keys, err)
	}
	if _, err := p.ExchangeCode(ctx, "default", tokenValues, client); err == nil {
		t.Fatal("code reused")
	}
	if _, err := p.UserInfo(ctx, "default", response.AccessToken); err == nil {
		t.Fatal("token from reused code was not revoked")
	}
	if _, err := p.UserInfo(ctx, "missing", response.AccessToken); err == nil {
		t.Fatal("issuer mismatch accepted")
	}
	if _, err := p.UserInfo(ctx, "default", "invalid"); err == nil {
		t.Fatal("invalid token accepted")
	}
}

func verifyToken(t *testing.T, p *Provider, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	headerData, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]any
	_ = json.Unmarshal(headerData, &header)
	payloadData, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(payloadData, &claims)
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	key, _ := p.Keys.Active(context.Background(), claims["iss"].(string))
	private, _ := parsePrivate(key)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestExchangeErrors(t *testing.T) {
	p, _ := newTestProvider(t)
	ctx := context.Background()
	client, _ := p.AuthenticateClient(ctx, "public", "none", "")
	for _, values := range []url.Values{{}, {"grant_type": {"refresh_token"}, "code": {"x"}, "client_id": {"public"}, "redirect_uri": {"https://app.example/callback"}}, {"grant_type": {"authorization_code"}, "code": {"missing"}, "client_id": {"public"}, "redirect_uri": {"https://app.example/callback"}}} {
		if _, err := p.ExchangeCode(ctx, "default", values, client); err == nil {
			t.Fatal("invalid exchange accepted")
		}
	}
}

func TestExchangeRejectsMalformedPKCEVerifier(t *testing.T) {
	p, _ := newTestProvider(t)
	ctx := context.Background()
	request, err := p.ValidateAuthorization(ctx, "default", validAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	code, err := p.IssueAuthorizationCode(ctx, request, "user", time.Unix(1_999_999_900, 0))
	if err != nil {
		t.Fatal(err)
	}
	client, _ := p.AuthenticateClient(ctx, "public", "none", "")
	values := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"public"},
		"redirect_uri":  {"https://app.example/callback"},
		"code_verifier": {"too-short"},
	}
	if _, err := p.ExchangeCode(ctx, "default", values, client); err == nil {
		t.Fatal("malformed PKCE verifier accepted")
	}
}
