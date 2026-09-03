package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/laibulle/robine-id/internal/domain"
	"github.com/laibulle/robine-id/internal/ports"
)

type Repository struct {
	Blobs              ports.BlobStore
	RootKey            string
	ApplicationsPrefix string
	ReloadInterval     time.Duration
	mu                 sync.RWMutex
	active             *domain.Snapshot
	lastChecked        time.Time
}

func (r *Repository) Load(ctx context.Context) (*domain.Snapshot, error) {
	data, err := r.Blobs.Read(ctx, r.RootKey)
	if err != nil {
		return nil, fmt.Errorf("read root configuration: %w", err)
	}
	var snapshot domain.Snapshot
	if err := decodeStrict(data, &snapshot); err != nil {
		return nil, fmt.Errorf("decode root configuration: %w", err)
	}
	keys, err := r.Blobs.List(ctx, r.ApplicationsPrefix)
	if err != nil && err != fs.ErrNotExist {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !strings.HasSuffix(key, ".json") {
			continue
		}
		clientData, readErr := r.Blobs.Read(ctx, key)
		if readErr != nil {
			return nil, fmt.Errorf("read application %s: %w", key, readErr)
		}
		var client domain.Client
		if err := decodeStrict(clientData, &client); err != nil {
			return nil, fmt.Errorf("decode application %s: %w", key, err)
		}
		applyClientDefaults(&client)
		snapshot.Clients = append(snapshot.Clients, client)
		data = append(data, clientData...)
	}
	applyDefaults(&snapshot)
	if err := Validate(&snapshot); err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(data)
	snapshot.Fingerprint = hex.EncodeToString(fingerprint[:])
	r.mu.Lock()
	r.active = &snapshot
	r.lastChecked = time.Now()
	r.mu.Unlock()
	return &snapshot, nil
}

func (r *Repository) Active(ctx context.Context) (*domain.Snapshot, error) {
	r.mu.RLock()
	active := r.active
	lastChecked := r.lastChecked
	r.mu.RUnlock()
	interval := r.ReloadInterval
	if interval == 0 {
		interval = time.Second
	}
	if active != nil && time.Since(lastChecked) < interval {
		return active, nil
	}
	loaded, err := r.Load(ctx)
	if err != nil && active != nil {
		return active, nil
	}
	return loaded, err
}

func decodeStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.More() {
		return fmt.Errorf("multiple JSON values")
	}
	return nil
}

func applyDefaults(s *domain.Snapshot) {
	if s.Branding.ProductName == "" {
		s.Branding.ProductName = "Robine ID"
	}
	if s.Branding.PrimaryColor == "" {
		s.Branding.PrimaryColor = "#176b70"
	}
	if s.Branding.DefaultLocale == "" {
		s.Branding.DefaultLocale = "en"
	}
	for index := range s.Issuers {
		issuer := &s.Issuers[index]
		if len(issuer.Scopes) == 0 {
			issuer.Scopes = []string{"openid", "profile", "email"}
		}
		if issuer.TokenPolicy.AuthorizationCodeLifetime == 0 {
			issuer.TokenPolicy.AuthorizationCodeLifetime = 60
		}
		if issuer.TokenPolicy.IDTokenLifetime == 0 {
			issuer.TokenPolicy.IDTokenLifetime = 300
		}
		if issuer.TokenPolicy.AccessTokenLifetime == 0 {
			issuer.TokenPolicy.AccessTokenLifetime = 300
		}
		if issuer.TokenPolicy.ClockSkew == 0 {
			issuer.TokenPolicy.ClockSkew = 30
		}
	}
	if s.Authentication.Session.IdleTimeout == 0 {
		s.Authentication.Session.IdleTimeout = 1800
	}
	if s.Authentication.Session.AbsoluteTimeout == 0 {
		s.Authentication.Session.AbsoluteTimeout = 28800
	}
	if s.Authentication.Session.MaxConcurrent == 0 {
		s.Authentication.Session.MaxConcurrent = 5
	}
	if s.Authentication.RateLimit.Attempts == 0 {
		s.Authentication.RateLimit.Attempts = 5
	}
	if s.Authentication.RateLimit.WindowSeconds == 0 {
		s.Authentication.RateLimit.WindowSeconds = 60
	}
}

func applyClientDefaults(c *domain.Client) {
	if c.Name == "" {
		c.Name = c.ID
	}
	if c.Type == "" {
		c.Type = "public"
	}
	if c.AuthenticationMethod == "" {
		if len(c.AuthenticationMethods) > 0 {
			c.AuthenticationMethod = c.AuthenticationMethods[0]
		} else if c.Type == "public" {
			c.AuthenticationMethod = "none"
		} else {
			c.AuthenticationMethod = "client_secret_basic"
		}
	}
	if len(c.AuthenticationMethods) == 0 {
		c.AuthenticationMethods = []string{c.AuthenticationMethod}
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid"}
	}
	if len(c.GrantTypes) == 0 {
		c.GrantTypes = []string{"authorization_code"}
	}
}

func Validate(s *domain.Snapshot) error {
	if s.SchemaVersion != 1 {
		return fmt.Errorf("schema_version must be 1")
	}
	if len(s.Issuers) == 0 {
		return fmt.Errorf("at least one issuer is required")
	}
	issuerIDs := map[string]bool{}
	for _, issuer := range s.Issuers {
		if issuer.ID == "" || issuerIDs[issuer.ID] {
			return fmt.Errorf("issuer IDs must be non-empty and unique")
		}
		issuerIDs[issuer.ID] = true
		parsed, err := url.Parse(issuer.URL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("issuer %s URL must be absolute", issuer.ID)
		}
		for _, value := range []int{issuer.TokenPolicy.AuthorizationCodeLifetime, issuer.TokenPolicy.IDTokenLifetime, issuer.TokenPolicy.AccessTokenLifetime, issuer.TokenPolicy.ClockSkew} {
			if value < 1 || value > 86400 {
				return fmt.Errorf("issuer %s token policy must be between 1 and 86400 seconds", issuer.ID)
			}
		}
	}
	clientIDs := map[string]bool{}
	for _, client := range s.Clients {
		if client.SchemaVersion != 1 || client.Kind != "oidc_application" {
			return fmt.Errorf("client %s must be schema_version 1 oidc_application", client.ID)
		}
		if client.ID == "" || clientIDs[client.ID] {
			return fmt.Errorf("client IDs must be non-empty and unique")
		}
		clientIDs[client.ID] = true
		if client.Type != "public" && client.Type != "confidential" {
			return fmt.Errorf("client %s has invalid type", client.ID)
		}
		if len(client.RedirectURIs) == 0 {
			return fmt.Errorf("client %s requires redirect_uris", client.ID)
		}
		for _, raw := range append(append([]string{}, client.RedirectURIs...), client.PostLogoutRedirectURIs...) {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" || u.User != nil {
				return fmt.Errorf("client %s has invalid redirect URI", client.ID)
			}
			loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
			if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
				return fmt.Errorf("client %s redirect URI must use HTTPS", client.ID)
			}
		}
		if client.Type == "public" && (client.AuthenticationMethod != "none" || !client.RequiresPKCE() || !client.RequiresNonce()) {
			return fmt.Errorf("public client %s has insecure policy", client.ID)
		}
		if client.Type == "confidential" && client.AuthenticationMethod != "client_secret_basic" && client.AuthenticationMethod != "client_secret_post" {
			return fmt.Errorf("confidential client %s has invalid authentication", client.ID)
		}
		if client.Type == "confidential" && client.SecretReference.Literal == "" && client.SecretReference.Key == "" {
			return fmt.Errorf("confidential client %s requires secret_reference", client.ID)
		}
	}
	reservedClaims := map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true, "nonce": true, "auth_time": true}
	for claim, mapping := range s.Claims {
		if reservedClaims[claim] {
			return fmt.Errorf("claim %s is reserved", claim)
		}
		if mapping.Source == "" || mapping.Scope == "" {
			return fmt.Errorf("claim %s requires source and scope", claim)
		}
	}
	if err := validatePrimaryColor(s.Branding.PrimaryColor); err != nil {
		return err
	}
	return nil
}

func validatePrimaryColor(value string) error {
	if !strings.HasPrefix(value, "#") || len(value) != 7 {
		return fmt.Errorf("primary_color must be a six-digit hexadecimal color")
	}
	rgb, err := strconv.ParseUint(value[1:], 16, 24)
	if err != nil {
		return fmt.Errorf("primary_color must be a six-digit hexadecimal color")
	}
	channels := []float64{float64(rgb>>16) / 255, float64((rgb>>8)&255) / 255, float64(rgb&255) / 255}
	for index, channel := range channels {
		if channel <= 0.04045 {
			channels[index] = channel / 12.92
		} else {
			channels[index] = math.Pow((channel+0.055)/1.055, 2.4)
		}
	}
	luminance := 0.2126*channels[0] + 0.7152*channels[1] + 0.0722*channels[2]
	if 1.05/(luminance+0.05) < 4.5 {
		return fmt.Errorf("primary_color must have at least 4.5:1 contrast with white")
	}
	return nil
}

func ApplicationPrefix(rootKey string) string { return path.Join(path.Dir(rootKey), "applications") }
