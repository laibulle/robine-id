package domain

import (
	"encoding/json"
	"testing"
)

func TestSecretReference(t *testing.T) {
	var literal SecretReference
	if err := json.Unmarshal([]byte(`"secret"`), &literal); err != nil || literal.Literal != "secret" {
		t.Fatalf("literal: %#v %v", literal, err)
	}
	var environment SecretReference
	if err := json.Unmarshal([]byte(`{"provider":"env","key":"CLIENT_SECRET"}`), &environment); err != nil || environment.Key != "CLIENT_SECRET" {
		t.Fatalf("environment: %#v %v", environment, err)
	}
	for _, invalid := range []string{`""`, `{}`, `{"provider":"file","key":"x"}`, `{"provider":"env","key":"x","other":true}`} {
		if json.Unmarshal([]byte(invalid), &SecretReference{}) == nil {
			t.Errorf("expected %s to fail", invalid)
		}
	}
}

func TestPolicyDefaults(t *testing.T) {
	client := Client{Type: "public"}
	if !client.RequiresPKCE() || !client.RequiresNonce() || !client.RequiresConsent() {
		t.Fatal("public defaults must be secure")
	}
	no := false
	client = Client{Type: "confidential", PKCERequired: &no, NonceRequired: &no, ConsentRequired: &no}
	if client.RequiresPKCE() || client.RequiresNonce() || client.RequiresConsent() {
		t.Fatal("explicit policy ignored")
	}
	if !(User{}).IsEnabled() {
		t.Fatal("users default to enabled")
	}
	disabled := false
	if (User{Enabled: &disabled}).IsEnabled() {
		t.Fatal("disabled user enabled")
	}
	problem := NewProtocolError("invalid_request", "bad")
	if problem.Error() != "invalid_request: bad" {
		t.Fatalf("unexpected error: %s", problem)
	}
}
