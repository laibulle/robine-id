package application

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/laibulle/robine-id/internal/domain"
	"github.com/laibulle/robine-id/internal/ports"
)

type Provider struct {
	Config      ports.ConfigurationRepository
	Accounts    ports.AccountRepository
	Codes       ports.AuthorizationCodeStore
	Tokens      ports.AccessTokenStore
	Sessions    ports.SessionRegistry
	Limits      ports.RateLimiter
	Keys        ports.KeyStore
	Passwords   ports.PasswordHasher
	Clock       ports.Clock
	Audit       ports.AuditSink
	Environment func(string) string
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

func (p *Provider) now() time.Time {
	if p.Clock != nil {
		return p.Clock.Now()
	}
	return realClock{}.Now()
}

func (p *Provider) snapshot(ctx context.Context) (*domain.Snapshot, error) {
	return p.Config.Active(ctx)
}

func findIssuer(snapshot *domain.Snapshot, id string) (domain.Issuer, error) {
	for _, issuer := range snapshot.Issuers {
		if issuer.ID == id {
			return issuer, nil
		}
	}
	return domain.Issuer{}, domain.ErrNotFound
}

func findClient(snapshot *domain.Snapshot, id string) (domain.Client, error) {
	for _, client := range snapshot.Clients {
		if client.ID == id {
			return client, nil
		}
	}
	return domain.Client{}, domain.ErrNotFound
}

func findUserByIdentifier(snapshot *domain.Snapshot, identifier string) (domain.User, error) {
	normalized := strings.ToLower(strings.TrimSpace(identifier))
	for _, user := range snapshot.Users {
		if strings.ToLower(user.Identifier) == normalized {
			return user, nil
		}
	}
	return domain.User{}, domain.ErrNotFound
}

func findUser(snapshot *domain.Snapshot, id string) (domain.User, error) {
	for _, user := range snapshot.Users {
		if user.ID == id {
			return user, nil
		}
	}
	return domain.User{}, domain.ErrNotFound
}

func (p *Provider) managedUser(ctx context.Context, configured domain.User) domain.User {
	if p.Accounts == nil {
		return configured
	}
	override, err := p.Accounts.Get(ctx, configured.ID)
	if err != nil {
		return configured
	}
	override.Identifier = configured.Identifier
	return override
}

func (p *Provider) UserByID(ctx context.Context, id string) (domain.User, error) {
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return domain.User{}, err
	}
	configured, err := findUser(snapshot, id)
	if err != nil {
		return domain.User{}, err
	}
	return p.managedUser(ctx, configured), nil
}

func (p *Provider) ListUsers(ctx context.Context) ([]domain.User, error) {
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	users := make([]domain.User, 0, len(snapshot.Users))
	for _, configured := range snapshot.Users {
		users = append(users, p.managedUser(ctx, configured))
	}
	return users, nil
}

func (p *Provider) Discovery(ctx context.Context, issuerID string) (map[string]any, error) {
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	issuer, err := findIssuer(snapshot, issuerID)
	if err != nil {
		return nil, err
	}
	base := strings.TrimSuffix(issuer.URL, "/")
	claims := []string{"sub", "iss", "aud", "iat", "exp", "auth_time", "nonce"}
	for claim := range snapshot.Claims {
		if !slices.Contains(claims, claim) {
			claims = append(claims, claim)
		}
	}
	result := map[string]any{
		"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token",
		"userinfo_endpoint": base + "/userinfo", "jwks_uri": base + "/jwks.json", "end_session_endpoint": base + "/logout",
		"response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"},
		"grant_types_supported": []string{"authorization_code"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"scopes_supported":                      issuer.Scopes, "claims_supported": claims, "claims_parameter_supported": true,
		"request_parameter_supported": false, "request_uri_parameter_supported": false,
	}
	if len(snapshot.Branding.Locales) > 0 {
		result["ui_locales_supported"] = snapshot.Branding.Locales
	}
	return result, nil
}

func protocol(code, description string) error { return domain.NewProtocolError(code, description) }

func required(values url.Values, names ...string) error {
	for _, name := range names {
		if values.Get(name) == "" {
			return protocol("invalid_request", "missing or invalid "+name)
		}
	}
	return nil
}

func (p *Provider) ValidateAuthorization(ctx context.Context, issuerID string, values url.Values) (domain.AuthorizationRequest, error) {
	if err := required(values, "client_id", "redirect_uri", "response_type", "scope"); err != nil {
		return domain.AuthorizationRequest{}, err
	}
	if values.Get("response_type") != "code" {
		return domain.AuthorizationRequest{}, protocol("unsupported_response_type", "only code is supported")
	}
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return domain.AuthorizationRequest{}, err
	}
	if _, err := findIssuer(snapshot, issuerID); err != nil {
		return domain.AuthorizationRequest{}, protocol("invalid_request", "unknown issuer")
	}
	client, err := findClient(snapshot, values.Get("client_id"))
	if err != nil {
		return domain.AuthorizationRequest{}, protocol("invalid_request", "unknown client")
	}
	if !slices.Contains(client.GrantTypes, "authorization_code") {
		return domain.AuthorizationRequest{}, protocol("unauthorized_client", "authorization_code is not allowed")
	}
	if !slices.Contains(client.RedirectURIs, values.Get("redirect_uri")) {
		return domain.AuthorizationRequest{}, protocol("invalid_request", "redirect_uri is not registered")
	}
	requested := strings.Fields(values.Get("scope"))
	if !slices.Contains(requested, "openid") {
		return domain.AuthorizationRequest{}, protocol("invalid_scope", "openid scope is required")
	}
	seen := map[string]bool{}
	for _, scope := range requested {
		if seen[scope] || !slices.Contains(client.Scopes, scope) {
			return domain.AuthorizationRequest{}, protocol("invalid_scope", "one or more scopes are invalid")
		}
		seen[scope] = true
	}
	nonce := values.Get("nonce")
	if client.RequiresNonce() && nonce == "" {
		return domain.AuthorizationRequest{}, protocol("invalid_request", "missing or invalid nonce")
	}
	challenge := values.Get("code_challenge")
	method := values.Get("code_challenge_method")
	if client.RequiresPKCE() || challenge != "" || method != "" {
		if method != "S256" || len(challenge) < 43 || len(challenge) > 128 || !urlSafe(challenge) {
			return domain.AuthorizationRequest{}, protocol("invalid_request", "PKCE S256 is required")
		}
	}
	prompts := strings.Fields(values.Get("prompt"))
	supported := []string{"none", "login", "consent", "select_account"}
	for _, promptValue := range prompts {
		if !slices.Contains(supported, promptValue) {
			return domain.AuthorizationRequest{}, protocol("invalid_request", "prompt contains an unsupported value")
		}
	}
	if slices.Contains(prompts, "none") && len(prompts) != 1 {
		return domain.AuthorizationRequest{}, protocol("invalid_request", "prompt none cannot be combined")
	}
	var maxAge *int
	if raw := values.Get("max_age"); raw != "" {
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value < 0 {
			return domain.AuthorizationRequest{}, protocol("invalid_request", "max_age must be non-negative")
		}
		maxAge = &value
	}
	locale := ""
	if locales := strings.Fields(values.Get("ui_locales")); len(locales) > 0 {
		locale = locales[0]
	}
	return domain.AuthorizationRequest{IssuerID: issuerID, ClientID: client.ID, RedirectURI: values.Get("redirect_uri"), Scopes: requested, State: values.Get("state"), Nonce: nonce, CodeChallenge: challenge, CodeChallengeMethod: method, Locale: locale, Prompt: prompts, MaxAge: maxAge}, nil
}

func urlSafe(value string) bool {
	for _, char := range value {
		if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func (p *Provider) Authenticate(ctx context.Context, identifier, password, remote string) (domain.User, time.Duration, error) {
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return domain.User{}, 0, err
	}
	policy := snapshot.Authentication.RateLimit
	keyHash := sha256.Sum256([]byte(remote + "\x00" + strings.ToLower(strings.TrimSpace(identifier))))
	allowed, retry := p.Limits.Allow(ctx, base64.RawURLEncoding.EncodeToString(keyHash[:]), policy.Attempts, time.Duration(policy.WindowSeconds)*time.Second, p.now())
	if !allowed {
		return domain.User{}, retry, protocol("rate_limited", "authentication temporarily unavailable")
	}
	user, err := findUserByIdentifier(snapshot, identifier)
	if err == nil {
		user = p.managedUser(ctx, user)
	}
	valid := err == nil && user.IsEnabled() && p.Passwords.Compare(user.PasswordHash, password)
	if !valid {
		return domain.User{}, 0, protocol("invalid_credentials", "invalid identifier or password")
	}
	return user, 0, nil
}

func (p *Provider) StartSession(ctx context.Context, subject string) (domain.Session, error) {
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return domain.Session{}, err
	}
	return p.Sessions.Start(ctx, subject, p.now(), snapshot.Authentication.Session.MaxConcurrent)
}

func (p *Provider) ValidateSession(ctx context.Context, id string) (domain.Session, error) {
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return domain.Session{}, err
	}
	return p.Sessions.Validate(ctx, id, p.now(), snapshot.Authentication.Session)
}

func (p *Provider) EndSession(ctx context.Context, id string) error { return p.Sessions.End(ctx, id) }

func (p *Provider) IssueAuthorizationCode(ctx context.Context, request domain.AuthorizationRequest, subject string, authTime time.Time) (string, error) {
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return "", err
	}
	issuer, err := findIssuer(snapshot, request.IssuerID)
	if err != nil {
		return "", err
	}
	user, err := p.UserByID(ctx, subject)
	if err != nil {
		return "", protocol("access_denied", "identity is unavailable")
	}
	if !user.IsEnabled() {
		return "", protocol("access_denied", "identity is unavailable")
	}
	claims := mapClaims(snapshot, user, request.Scopes)
	grant := domain.AuthorizationGrant{Issuer: strings.TrimSuffix(issuer.URL, "/"), Subject: subject, ClientID: request.ClientID, RedirectURI: request.RedirectURI, Scopes: request.Scopes, Nonce: request.Nonce, CodeChallenge: request.CodeChallenge, ExpiresAt: p.now().Add(time.Duration(issuer.TokenPolicy.AuthorizationCodeLifetime) * time.Second), AuthTime: authTime, Claims: claims, IDTokenClaims: claims}
	return p.Codes.Issue(ctx, grant)
}

func mapClaims(snapshot *domain.Snapshot, user domain.User, scopes []string) map[string]any {
	result := map[string]any{}
	sources := map[string]any{"name": user.Name, "email": user.Email}
	for key, value := range user.Claims {
		sources[key] = value
	}
	for claim, mapping := range snapshot.Claims {
		if slices.Contains(scopes, mapping.Scope) {
			if value, ok := sources[mapping.Source]; ok && value != nil {
				result[claim] = value
			}
		}
	}
	return result
}

type TokenResponse struct {
	AccessToken, IDToken, TokenType, Scope string
	ExpiresIn                              int
}

func (p *Provider) AuthenticateClient(ctx context.Context, clientID, transport, secret string) (domain.Client, error) {
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return domain.Client{}, err
	}
	client, err := findClient(snapshot, clientID)
	if err != nil {
		return domain.Client{}, clientAuthError()
	}
	if client.Type == "public" {
		if transport != "none" || secret != "" {
			return domain.Client{}, clientAuthError()
		}
		return client, nil
	}
	if transport != client.AuthenticationMethod {
		return domain.Client{}, clientAuthError()
	}
	expected := client.SecretReference.Literal
	if client.SecretReference.Key != "" {
		expected = ""
		if p.Environment != nil {
			expected = p.Environment(client.SecretReference.Key)
		}
	}
	if expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(secret)) != 1 {
		return domain.Client{}, clientAuthError()
	}
	return client, nil
}

func clientAuthError() error {
	e := domain.NewProtocolError("invalid_client", "client authentication failed")
	e.Status = 401
	return e
}

func (p *Provider) ExchangeCode(ctx context.Context, issuerID string, values url.Values, client domain.Client) (TokenResponse, error) {
	if err := required(values, "grant_type", "code", "client_id", "redirect_uri"); err != nil {
		return TokenResponse{}, err
	}
	if values.Get("grant_type") != "authorization_code" {
		return TokenResponse{}, protocol("unsupported_grant_type", "only authorization_code is supported")
	}
	if values.Get("client_id") != client.ID {
		return TokenResponse{}, protocol("invalid_grant", "authorization code is invalid")
	}
	grant, err := p.Codes.Consume(ctx, values.Get("code"))
	var reused *domain.AuthorizationCodeReuseError
	if errors.As(err, &reused) {
		if reused.AccessToken != "" {
			_ = p.Tokens.Revoke(ctx, reused.AccessToken)
		}
		return TokenResponse{}, protocol("invalid_grant", "authorization code is invalid")
	}
	if errors.Is(err, domain.ErrAlreadyUsed) {
		return TokenResponse{}, protocol("invalid_grant", "authorization code is invalid")
	}
	if err != nil {
		return TokenResponse{}, protocol("invalid_grant", "authorization code is invalid")
	}
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return TokenResponse{}, err
	}
	issuer, err := findIssuer(snapshot, issuerID)
	if err != nil {
		return TokenResponse{}, protocol("invalid_grant", "authorization code is invalid")
	}
	if !p.now().Before(grant.ExpiresAt) || grant.Issuer != strings.TrimSuffix(issuer.URL, "/") || grant.ClientID != client.ID || grant.RedirectURI != values.Get("redirect_uri") {
		return TokenResponse{}, protocol("invalid_grant", "authorization code is invalid")
	}
	if grant.CodeChallenge != "" {
		verifier := values.Get("code_verifier")
		if !validPKCEVerifier(verifier) {
			return TokenResponse{}, protocol("invalid_grant", "authorization code is invalid")
		}
		calculated := sha256.Sum256([]byte(verifier))
		encoded := base64.RawURLEncoding.EncodeToString(calculated[:])
		if subtle.ConstantTimeCompare([]byte(encoded), []byte(grant.CodeChallenge)) != 1 {
			return TokenResponse{}, protocol("invalid_grant", "authorization code is invalid")
		}
	}
	idToken, err := p.issueIDToken(ctx, grant, issuer.TokenPolicy.IDTokenLifetime)
	if err != nil {
		return TokenResponse{}, err
	}
	accessGrant := domain.AccessGrant{Issuer: grant.Issuer, Subject: grant.Subject, ClientID: grant.ClientID, Scopes: grant.Scopes, ExpiresAt: p.now().Add(time.Duration(issuer.TokenPolicy.AccessTokenLifetime) * time.Second), Claims: grant.Claims}
	accessToken, err := p.Tokens.Issue(ctx, accessGrant)
	if err != nil {
		return TokenResponse{}, err
	}
	if err := p.Codes.MarkExchanged(ctx, values.Get("code"), accessToken); err != nil {
		p.Tokens.Revoke(ctx, accessToken)
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: accessToken, IDToken: idToken, TokenType: "Bearer", Scope: strings.Join(grant.Scopes, " "), ExpiresIn: issuer.TokenPolicy.AccessTokenLifetime}, nil
}

func (p *Provider) ensureKey(ctx context.Context, issuer string) (domain.SigningKey, error) {
	key, err := p.Keys.Active(ctx, issuer)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return domain.SigningKey{}, err
	}
	return p.Keys.Rotate(ctx, issuer, "initial")
}

func parsePrivate(key domain.SigningKey) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key.PrivatePEM)
	if block == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func (p *Provider) issueIDToken(ctx context.Context, grant domain.AuthorizationGrant, lifetime int) (string, error) {
	key, err := p.ensureKey(ctx, grant.Issuer)
	if err != nil {
		return "", err
	}
	private, err := parsePrivate(key)
	if err != nil {
		return "", err
	}
	now := p.now().Unix()
	claims := map[string]any{"iss": grant.Issuer, "sub": grant.Subject, "aud": grant.ClientID, "iat": now, "exp": now + int64(lifetime), "auth_time": grant.AuthTime.Unix()}
	if grant.Nonce != "" {
		claims["nonce"] = grant.Nonce
	}
	for name, value := range grant.IDTokenClaims {
		claims[name] = value
	}
	return signJWT(private, key.ID, claims)
}

func signJWT(private *rsa.PrivateKey, keyID string, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": keyID})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(nil, private, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (p *Provider) JWKS(ctx context.Context, issuerID string) (map[string]any, error) {
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	issuer, err := findIssuer(snapshot, issuerID)
	if err != nil {
		return nil, err
	}
	issuerURL := strings.TrimSuffix(issuer.URL, "/")
	if _, err := p.ensureKey(ctx, issuerURL); err != nil {
		return nil, err
	}
	keys, err := p.Keys.All(ctx, issuerURL)
	if err != nil {
		return nil, err
	}
	public := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		private, parseErr := parsePrivate(key)
		if parseErr != nil {
			return nil, parseErr
		}
		public = append(public, map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": key.ID, "n": base64.RawURLEncoding.EncodeToString(private.PublicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})})
	}
	return map[string]any{"keys": public}, nil
}

func (p *Provider) UserInfo(ctx context.Context, issuerID, token string) (map[string]any, error) {
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	issuer, err := findIssuer(snapshot, issuerID)
	if err != nil {
		return nil, domain.ErrNotFound
	}
	grant, err := p.Tokens.Get(ctx, token)
	if err != nil || !p.now().Before(grant.ExpiresAt) || grant.Issuer != strings.TrimSuffix(issuer.URL, "/") {
		return nil, protocol("invalid_token", "bearer token is invalid")
	}
	user, err := p.UserByID(ctx, grant.Subject)
	if err != nil || !user.IsEnabled() {
		return nil, protocol("invalid_token", "bearer token is invalid")
	}
	result := map[string]any{"sub": grant.Subject}
	for name, value := range grant.Claims {
		result[name] = value
	}
	return result, nil
}

type ProfileUpdate struct{ Name, Email, CurrentPassword, NewPassword, PasswordConfirmation string }

func (p *Provider) UpdateProfile(ctx context.Context, subject string, update ProfileUpdate) (domain.User, error) {
	user, err := p.UserByID(ctx, subject)
	if err != nil {
		return domain.User{}, err
	}
	validation := domain.ValidationError{}
	update.Name = strings.TrimSpace(update.Name)
	update.Email = strings.TrimSpace(update.Email)
	if update.Name == "" || len(update.Name) > 160 {
		validation["name"] = "must contain between 1 and 160 characters"
	}
	if !validEmail(update.Email) {
		validation["email"] = "must be a valid email address"
	}
	if update.NewPassword != "" {
		if len(update.NewPassword) < 12 || len(update.NewPassword) > 128 {
			validation["new_password"] = "must contain between 12 and 128 characters"
		}
		if update.NewPassword != update.PasswordConfirmation {
			validation["password_confirmation"] = "does not match the new password"
		}
		if !p.Passwords.Compare(user.PasswordHash, update.CurrentPassword) {
			validation["current_password"] = "is incorrect"
		}
	}
	if len(validation) > 0 {
		return domain.User{}, validation
	}
	user.Name, user.Email = update.Name, update.Email
	if update.NewPassword != "" {
		hash, err := p.Passwords.Hash(update.NewPassword)
		if err != nil {
			return domain.User{}, err
		}
		user.PasswordHash = hash
	}
	claims := make(map[string]any, len(user.Claims)+1)
	for name, value := range user.Claims {
		claims[name] = value
	}
	claims["updated_at"] = p.now().Unix()
	user.Claims = claims
	if p.Accounts == nil {
		return domain.User{}, fmt.Errorf("account repository is unavailable")
	}
	if err := p.Accounts.Save(ctx, user); err != nil {
		return domain.User{}, err
	}
	return user, nil
}

func validPKCEVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("-._~", char) {
			continue
		}
		return false
	}
	return true
}

type AdminUpdate struct {
	Name, Email, Roles string
	Enabled            bool
}

func (p *Provider) UpdateUserAsAdmin(ctx context.Context, actorID, targetID string, update AdminUpdate) (domain.User, error) {
	actor, err := p.UserByID(ctx, actorID)
	if err != nil || !Admin(actor) {
		return domain.User{}, protocol("access_denied", "administrator access required")
	}
	target, err := p.UserByID(ctx, targetID)
	if err != nil {
		return domain.User{}, err
	}
	validation := domain.ValidationError{}
	update.Name = strings.TrimSpace(update.Name)
	update.Email = strings.TrimSpace(update.Email)
	roles := parseRoles(update.Roles)
	if update.Name == "" || len(update.Name) > 160 {
		validation["name"] = "must contain between 1 and 160 characters"
	}
	if !validEmail(update.Email) {
		validation["email"] = "must be a valid email address"
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if seen[role] || !validRole(role) {
			validation["roles"] = "must contain unique lowercase role identifiers"
		}
		seen[role] = true
	}
	if actorID == targetID {
		if !update.Enabled {
			validation["enabled"] = "cannot disable your own account"
		}
		if !slices.Contains(roles, "admin") {
			validation["roles"] = "cannot remove your own admin role"
		}
	}
	if len(validation) > 0 {
		return domain.User{}, validation
	}
	target.Name, target.Email, target.Roles, target.Enabled = update.Name, update.Email, roles, &update.Enabled
	if p.Accounts == nil {
		return domain.User{}, fmt.Errorf("account repository is unavailable")
	}
	if err := p.Accounts.Save(ctx, target); err != nil {
		return domain.User{}, err
	}
	return target, nil
}

func Admin(user domain.User) bool { return user.IsEnabled() && slices.Contains(user.Roles, "admin") }
func validEmail(value string) bool {
	at := strings.IndexByte(value, '@')
	return at > 0 && at < len(value)-3 && strings.Contains(value[at+1:], ".") && !strings.ContainsAny(value, " \t\r\n")
}
func parseRoles(value string) []string {
	var roles []string
	for _, role := range strings.Split(value, ",") {
		if role = strings.TrimSpace(role); role != "" {
			roles = append(roles, role)
		}
	}
	return roles
}
func validRole(value string) bool {
	if len(value) < 1 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == ':' || char == '_' || char == '-') {
			return false
		}
	}
	return true
}

func (p *Provider) VerifyIDToken(ctx context.Context, issuerID, token string) (map[string]any, error) {
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	issuer, err := findIssuer(snapshot, issuerID)
	if err != nil {
		return nil, protocol("invalid_request", "ID token is invalid")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, protocol("invalid_request", "ID token is invalid")
	}
	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, protocol("invalid_request", "ID token is invalid")
	}
	payloadData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, protocol("invalid_request", "ID token is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, protocol("invalid_request", "ID token is invalid")
	}
	var header map[string]any
	var claims map[string]any
	if json.Unmarshal(headerData, &header) != nil || json.Unmarshal(payloadData, &claims) != nil || header["alg"] != "RS256" {
		return nil, protocol("invalid_request", "ID token is invalid")
	}
	kid, ok := header["kid"].(string)
	if !ok || kid == "" {
		return nil, protocol("invalid_request", "ID token is invalid")
	}
	keys, err := p.Keys.All(ctx, strings.TrimSuffix(issuer.URL, "/"))
	if err != nil {
		return nil, err
	}
	var signingKey *domain.SigningKey
	for index := range keys {
		if keys[index].ID == kid {
			signingKey = &keys[index]
			break
		}
	}
	if signingKey == nil {
		return nil, protocol("invalid_request", "ID token is invalid")
	}
	private, err := parsePrivate(*signingKey)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA256, digest[:], signature) != nil {
		return nil, protocol("invalid_request", "ID token is invalid")
	}
	if claims["iss"] != strings.TrimSuffix(issuer.URL, "/") {
		return nil, protocol("invalid_request", "ID token is invalid")
	}
	expires, ok := claims["exp"].(float64)
	if !ok || p.now().Unix() > int64(expires)+int64(issuer.TokenPolicy.ClockSkew) {
		return nil, protocol("invalid_request", "ID token is invalid")
	}
	if _, ok := claims["sub"].(string); !ok {
		return nil, protocol("invalid_request", "ID token is invalid")
	}
	return claims, nil
}
