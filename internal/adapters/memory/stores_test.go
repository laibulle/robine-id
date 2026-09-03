package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/laibulle/robine-id/internal/domain"
)

func TestAuthorizationCodeLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewAuthorizationCodes()
	grant := domain.AuthorizationGrant{Subject: "user"}
	code, err := store.Issue(ctx, grant)
	if err != nil || code == "" {
		t.Fatal(err)
	}
	got, err := store.Consume(ctx, code)
	if err != nil || got.Subject != "user" {
		t.Fatalf("consume: %#v %v", got, err)
	}
	if _, err := store.Consume(ctx, code); !errors.Is(err, domain.ErrAlreadyUsed) {
		t.Fatalf("expected reuse, got %v", err)
	}
	if _, err := store.Consume(ctx, "unknown"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected missing, got %v", err)
	}
	if err := store.MarkExchanged(ctx, code, "access"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkExchanged(ctx, "unknown", "access"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestAccessTokens(t *testing.T) {
	ctx := context.Background()
	store := NewAccessTokens()
	token, err := store.Issue(ctx, domain.AccessGrant{Subject: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if grant, err := store.Get(ctx, token); err != nil || grant.Subject != "user" {
		t.Fatalf("get: %#v %v", grant, err)
	}
	if err := store.Revoke(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, token); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestSessionsEnforceAgeAndMaximum(t *testing.T) {
	ctx := context.Background()
	store := NewSessions()
	now := time.Unix(1000, 0)
	first, _ := store.Start(ctx, "user", now, 1)
	second, _ := store.Start(ctx, "user", now.Add(time.Second), 1)
	policy := domain.SessionPolicy{IdleTimeout: 10, AbsoluteTimeout: 20}
	if _, err := store.Validate(ctx, first.ID, now.Add(2*time.Second), policy); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("oldest session retained")
	}
	validated, err := store.Validate(ctx, second.ID, now.Add(2*time.Second), policy)
	if err != nil || !validated.LastSeenAt.Equal(now.Add(2*time.Second)) {
		t.Fatal(err)
	}
	if _, err := store.Validate(ctx, second.ID, now.Add(30*time.Second), policy); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("expired session retained")
	}
	third, _ := store.Start(ctx, "other", now, 2)
	if err := store.End(ctx, third.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Validate(ctx, third.ID, now, policy); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("ended session retained")
	}
}

func TestRateLimits(t *testing.T) {
	ctx := context.Background()
	limits := NewRateLimits()
	now := time.Unix(1000, 0)
	if allowed, _ := limits.Allow(ctx, "key", 1, time.Minute, now); !allowed {
		t.Fatal("first rejected")
	}
	if allowed, retry := limits.Allow(ctx, "key", 1, time.Minute, now.Add(time.Second)); allowed || retry != 59*time.Second {
		t.Fatalf("expected retry, got %v %v", allowed, retry)
	}
	if allowed, _ := limits.Allow(ctx, "key", 1, time.Minute, now.Add(61*time.Second)); !allowed {
		t.Fatal("window did not expire")
	}
}
