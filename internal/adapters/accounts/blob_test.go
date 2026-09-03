package accounts

import (
	"context"
	"errors"
	"testing"

	"github.com/laibulle/robine-id/internal/adapters/blob"
	"github.com/laibulle/robine-id/internal/domain"
)

func TestBlobAccountsRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := &Blob{Blobs: blob.Local{Root: t.TempDir()}, Key: "accounts.json"}
	if _, err := store.Get(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal(err)
	}
	user := domain.User{ID: "user", Identifier: "user@example.com", Name: "User"}
	if err := store.Save(ctx, user); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, "user")
	if err != nil || got.Name != "User" {
		t.Fatalf("got %#v %v", got, err)
	}
	user.Name = "Updated"
	if err := store.Save(ctx, user); err != nil {
		t.Fatal(err)
	}
	got, _ = store.Get(ctx, "user")
	if got.Name != "Updated" {
		t.Fatal("not updated")
	}
}
