package config

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/laibulle/robine-id/internal/domain"
)

type memoryBlobs struct {
	values  map[string][]byte
	listErr error
}

func (m *memoryBlobs) Read(_ context.Context, key string) ([]byte, error) {
	value, ok := m.values[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return value, nil
}
func (m *memoryBlobs) WriteAtomic(_ context.Context, key string, value []byte, _ fs.FileMode) error {
	m.values[key] = value
	return nil
}
func (m *memoryBlobs) List(_ context.Context, prefix string) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var keys []string
	for key := range m.values {
		if strings.HasPrefix(key, prefix+"/") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

const validRoot = `{
  "schema_version":1,
  "issuers":[{"id":"default","url":"https://id.example/default","scopes":["openid","profile"],"token_policy":{}}],
  "users":[{"id":"u1","identifier":"u@example.com","password_hash":"hash","name":"User","email":"u@example.com"}],
  "claims":{"name":{"source":"name","scope":"profile"}},
  "branding":{},"authentication":{},"storage":{},"telemetry":{},"reconciliation":{"deletion_policy":"disable"}
}`
const validClient = `{"schema_version":1,"kind":"oidc_application","id":"client","redirect_uris":["http://localhost:3000/callback"],"scopes":["openid","profile"]}`

func TestRepositoryLoadsComposedConfiguration(t *testing.T) {
	blobs := &memoryBlobs{values: map[string][]byte{"robine_id.json": []byte(validRoot), "applications/client.json": []byte(validClient), "applications/readme.txt": []byte("ignored")}}
	repository := &Repository{Blobs: blobs, RootKey: "robine_id.json", ApplicationsPrefix: "applications"}
	snapshot, err := repository.Active(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Branding.ProductName != "Robine ID" || snapshot.Issuers[0].TokenPolicy.IDTokenLifetime != 300 {
		t.Fatalf("defaults missing: %#v", snapshot)
	}
	if len(snapshot.Clients) != 1 || snapshot.Clients[0].AuthenticationMethod != "none" || snapshot.Fingerprint == "" {
		t.Fatalf("client: %#v", snapshot.Clients)
	}
	again, err := repository.Active(context.Background())
	if err != nil || again != snapshot {
		t.Fatal("active snapshot not cached")
	}
	if got := ApplicationPrefix("folder/root.json"); got != "folder/applications" {
		t.Fatalf("prefix %s", got)
	}
}

func TestActiveKeepsLastValidRevision(t *testing.T) {
	blobs := &memoryBlobs{values: map[string][]byte{"robine_id.json": []byte(validRoot), "applications/client.json": []byte(validClient)}}
	repository := &Repository{Blobs: blobs, RootKey: "robine_id.json", ApplicationsPrefix: "applications", ReloadInterval: -time.Second}
	first, err := repository.Active(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blobs.values["robine_id.json"] = []byte(`{"invalid":true}`)
	second, err := repository.Active(context.Background())
	if err != nil || second != first {
		t.Fatalf("last valid snapshot lost: %p %p %v", first, second, err)
	}
}

func TestRepositoryLoadFailures(t *testing.T) {
	tests := []struct {
		name     string
		values   map[string][]byte
		listErr  error
		contains string
	}{
		{"missing root", map[string][]byte{}, nil, "read root"},
		{"bad root", map[string][]byte{"root.json": []byte(`{"schema_version":1,"unknown":true}`)}, nil, "unknown"},
		{"list", map[string][]byte{"root.json": []byte(validRoot)}, errors.New("offline"), "list applications"},
		{"bad client", map[string][]byte{"root.json": []byte(validRoot), "apps/a.json": []byte(`{`)}, nil, "decode application"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := &Repository{Blobs: &memoryBlobs{values: test.values, listErr: test.listErr}, RootKey: "root.json", ApplicationsPrefix: "apps"}
			_, err := repo.Load(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func baseSnapshot() domain.Snapshot {
	return domain.Snapshot{SchemaVersion: 1, Issuers: []domain.Issuer{{ID: "issuer", URL: "https://id.example/issuer", TokenPolicy: domain.TokenPolicy{AuthorizationCodeLifetime: 60, IDTokenLifetime: 300, AccessTokenLifetime: 300, ClockSkew: 30}}}, Branding: domain.Branding{PrimaryColor: "#176b70"}}
}

func boolPointer(value bool) *bool { return &value }

func TestValidateRejectsUnsafeConfiguration(t *testing.T) {
	validPublic := domain.Client{SchemaVersion: 1, Kind: "oidc_application", ID: "client", Type: "public", RedirectURIs: []string{"http://localhost:3000/callback"}, AuthenticationMethod: "none", PKCERequired: boolPointer(true), NonceRequired: boolPointer(true)}
	tests := []struct {
		name   string
		mutate func(*domain.Snapshot)
	}{
		{"schema", func(s *domain.Snapshot) { s.SchemaVersion = 2 }},
		{"issuers", func(s *domain.Snapshot) { s.Issuers = nil }},
		{"issuer id", func(s *domain.Snapshot) { s.Issuers[0].ID = "" }},
		{"issuer duplicate", func(s *domain.Snapshot) { s.Issuers = append(s.Issuers, s.Issuers[0]) }},
		{"issuer url", func(s *domain.Snapshot) { s.Issuers[0].URL = "relative" }},
		{"token policy", func(s *domain.Snapshot) { s.Issuers[0].TokenPolicy.IDTokenLifetime = 90000 }},
		{"client document", func(s *domain.Snapshot) { c := validPublic; c.SchemaVersion = 2; s.Clients = []domain.Client{c} }},
		{"client id", func(s *domain.Snapshot) { c := validPublic; c.ID = ""; s.Clients = []domain.Client{c} }},
		{"duplicate client", func(s *domain.Snapshot) { s.Clients = []domain.Client{validPublic, validPublic} }},
		{"client type", func(s *domain.Snapshot) { c := validPublic; c.Type = "native"; s.Clients = []domain.Client{c} }},
		{"redirect required", func(s *domain.Snapshot) { c := validPublic; c.RedirectURIs = nil; s.Clients = []domain.Client{c} }},
		{"redirect invalid", func(s *domain.Snapshot) {
			c := validPublic
			c.RedirectURIs = []string{"http://example.com/cb"}
			s.Clients = []domain.Client{c}
		}},
		{"public auth", func(s *domain.Snapshot) {
			c := validPublic
			c.AuthenticationMethod = "client_secret_post"
			s.Clients = []domain.Client{c}
		}},
		{"confidential auth", func(s *domain.Snapshot) {
			c := validPublic
			c.Type = "confidential"
			c.AuthenticationMethod = "none"
			s.Clients = []domain.Client{c}
		}},
		{"confidential secret", func(s *domain.Snapshot) {
			c := validPublic
			c.Type = "confidential"
			c.AuthenticationMethod = "client_secret_basic"
			s.Clients = []domain.Client{c}
		}},
		{"color", func(s *domain.Snapshot) { s.Branding.PrimaryColor = "red" }},
		{"color contrast", func(s *domain.Snapshot) { s.Branding.PrimaryColor = "#ffffff" }},
		{"reserved claim", func(s *domain.Snapshot) {
			s.Claims = map[string]domain.ClaimMapping{"iss": {Source: "name", Scope: "profile"}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := baseSnapshot()
			test.mutate(&snapshot)
			if Validate(&snapshot) == nil {
				t.Fatal("configuration accepted")
			}
		})
	}
	snapshot := baseSnapshot()
	snapshot.Clients = []domain.Client{validPublic}
	if err := Validate(&snapshot); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
}

func TestDecodeStrictAndDefaults(t *testing.T) {
	var value map[string]int
	if err := decodeStrict([]byte(`{"a":1}`), &value); err != nil || !reflect.DeepEqual(value, map[string]int{"a": 1}) {
		t.Fatal(err)
	}
	client := domain.Client{ID: "x", Type: "confidential", AuthenticationMethods: []string{"client_secret_post"}}
	applyClientDefaults(&client)
	if client.Name != "x" || client.AuthenticationMethod != "client_secret_post" || !reflect.DeepEqual(client.Scopes, []string{"openid"}) {
		t.Fatalf("defaults: %#v", client)
	}
}
