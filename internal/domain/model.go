package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Snapshot is the complete, validated provider configuration active for a process.
type Snapshot struct {
	SchemaVersion  int                     `json:"schema_version"`
	Issuers        []Issuer                `json:"issuers"`
	Users          []User                  `json:"users"`
	Claims         map[string]ClaimMapping `json:"claims"`
	Branding       Branding                `json:"branding"`
	Authentication Authentication          `json:"authentication"`
	Reconciliation Reconciliation          `json:"reconciliation"`
	Storage        StorageConfig           `json:"storage"`
	Telemetry      TelemetryConfig         `json:"telemetry"`
	Clients        []Client                `json:"-"`
	Fingerprint    string                  `json:"-"`
}

type Issuer struct {
	ID          string      `json:"id"`
	URL         string      `json:"url"`
	Scopes      []string    `json:"scopes"`
	TokenPolicy TokenPolicy `json:"token_policy"`
	Branding    Branding    `json:"branding"`
}

type TokenPolicy struct {
	AuthorizationCodeLifetime int `json:"authorization_code_lifetime"`
	IDTokenLifetime           int `json:"id_token_lifetime"`
	AccessTokenLifetime       int `json:"access_token_lifetime"`
	ClockSkew                 int `json:"clock_skew"`
}

type SecretReference struct {
	Provider string `json:"provider"`
	Key      string `json:"key"`
	Literal  string `json:"-"`
}

func (r *SecretReference) UnmarshalJSON(data []byte) error {
	var literal string
	if json.Unmarshal(data, &literal) == nil {
		if literal == "" {
			return fmt.Errorf("secret reference must not be empty")
		}
		r.Literal = literal
		return nil
	}
	type wire SecretReference
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode((*wire)(r)); err != nil {
		return err
	}
	if r.Provider != "env" || r.Key == "" {
		return fmt.Errorf("secret reference must use a non-empty env key")
	}
	return nil
}

type Client struct {
	SchemaVersion          int             `json:"schema_version"`
	Kind                   string          `json:"kind"`
	ID                     string          `json:"id"`
	Name                   string          `json:"name"`
	Type                   string          `json:"type"`
	RedirectURIs           []string        `json:"redirect_uris"`
	PostLogoutRedirectURIs []string        `json:"post_logout_redirect_uris"`
	Scopes                 []string        `json:"scopes"`
	GrantTypes             []string        `json:"grant_types"`
	AuthenticationMethod   string          `json:"authentication_method"`
	AuthenticationMethods  []string        `json:"authentication_methods"`
	PKCERequired           *bool           `json:"pkce_required"`
	NonceRequired          *bool           `json:"nonce_required"`
	SecretReference        SecretReference `json:"secret_reference"`
	ConsentRequired        *bool           `json:"consent_required"`
	Branding               Branding        `json:"branding"`
}

func (c Client) RequiresPKCE() bool {
	return c.PKCERequired == nil || *c.PKCERequired || c.Type == "public"
}

func (c Client) RequiresNonce() bool {
	if c.NonceRequired != nil {
		return *c.NonceRequired
	}
	return c.Type == "public"
}

func (c Client) RequiresConsent() bool {
	return c.ConsentRequired == nil || *c.ConsentRequired
}

type User struct {
	ID           string         `json:"id"`
	Identifier   string         `json:"identifier"`
	PasswordHash string         `json:"password_hash"`
	Name         string         `json:"name"`
	Email        string         `json:"email"`
	Roles        []string       `json:"roles"`
	Claims       map[string]any `json:"claims"`
	Enabled      *bool          `json:"enabled"`
}

func (u User) IsEnabled() bool { return u.Enabled == nil || *u.Enabled }

type ClaimMapping struct {
	Source string `json:"source"`
	Scope  string `json:"scope"`
}

type Branding struct {
	ProductName   string                       `json:"product_name"`
	Logo          string                       `json:"logo"`
	Favicon       string                       `json:"favicon"`
	PrimaryColor  string                       `json:"primary_color"`
	FontFamily    string                       `json:"font_family"`
	SupportLink   string                       `json:"support_link"`
	PrivacyLink   string                       `json:"privacy_link"`
	TermsLink     string                       `json:"terms_link"`
	DefaultLocale string                       `json:"default_locale"`
	Locales       []string                     `json:"locales"`
	Messages      map[string]map[string]string `json:"messages"`
}

type Authentication struct {
	Methods   []string        `json:"methods"`
	Session   SessionPolicy   `json:"session"`
	RateLimit RateLimitPolicy `json:"rate_limit"`
}

type SessionPolicy struct {
	IdleTimeout     int `json:"idle_timeout"`
	AbsoluteTimeout int `json:"absolute_timeout"`
	MaxConcurrent   int `json:"max_concurrent"`
}

type RateLimitPolicy struct {
	Attempts      int `json:"attempts"`
	WindowSeconds int `json:"window_seconds"`
}

type StorageConfig struct {
	DatabasePath   any    `json:"database_path"`
	PoolSize       int    `json:"pool_size"`
	SigningKeyPath string `json:"signing_key_path"`
}

type TelemetryConfig struct {
	LogLevel string `json:"log_level"`
}

type Reconciliation struct {
	DeletionPolicy string `json:"deletion_policy"`
}

type AuthorizationRequest struct {
	IssuerID, ClientID, RedirectURI string
	Scopes                          []string
	State, Nonce                    string
	CodeChallenge                   string
	CodeChallengeMethod             string
	Locale                          string
	Prompt                          []string
	MaxAge                          *int
}

type AuthorizationGrant struct {
	Issuer, Subject, ClientID, RedirectURI string
	Scopes                                 []string
	Nonce, CodeChallenge                   string
	ExpiresAt, AuthTime                    time.Time
	Claims, IDTokenClaims                  map[string]any
}

type AccessGrant struct {
	Issuer, Subject, ClientID string
	Scopes                    []string
	ExpiresAt                 time.Time
	Claims                    map[string]any
}

type Session struct {
	ID, Subject           string
	StartedAt, LastSeenAt time.Time
}

type SigningKey struct {
	ID         string `json:"kid"`
	PrivatePEM []byte `json:"private_pem"`
	Active     bool   `json:"active"`
}
