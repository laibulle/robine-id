package keystore

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/laibulle/robine-id/internal/adapters/blob"
	"github.com/laibulle/robine-id/internal/domain"
)

const testSecret = "012345678901234567890123456789012345678901234567890123456789"

func TestEncryptedKeyStorePersistsAndRotates(t *testing.T) {
	ctx := context.Background()
	blobs := blob.Local{Root: t.TempDir()}
	store := &Encrypted{Blobs: blobs, Key: "keys.enc", Secret: testSecret}
	if _, err := store.Active(ctx, "issuer"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing active: %v", err)
	}
	first, err := store.Rotate(ctx, "issuer", "rotation-1")
	if err != nil || !first.Active || len(first.PrivatePEM) == 0 {
		t.Fatal(err)
	}
	again, err := store.Rotate(ctx, "issuer", "rotation-1")
	if err != nil || string(again.PrivatePEM) != string(first.PrivatePEM) {
		t.Fatal("rotation not idempotent")
	}
	second, err := store.Rotate(ctx, "issuer", "rotation-2")
	if err != nil || second.ID != "rotation-2" {
		t.Fatal(err)
	}
	keys, err := store.All(ctx, "issuer")
	if err != nil || len(keys) != 2 || keys[0].Active || !keys[1].Active {
		t.Fatalf("keys %#v %v", keys, err)
	}
	reloaded := &Encrypted{Blobs: blobs, Key: "keys.enc", Secret: testSecret}
	active, err := reloaded.Active(ctx, "issuer")
	if err != nil || active.ID != "rotation-2" {
		t.Fatalf("reload %#v %v", active, err)
	}
	wrong := &Encrypted{Blobs: blobs, Key: "keys.enc", Secret: testSecret + "wrong"}
	if _, err := wrong.All(ctx, "issuer"); err == nil {
		t.Fatal("wrong secret accepted")
	}
}

type errorBlobs struct{}

func (errorBlobs) Read(context.Context, string) ([]byte, error) { return nil, errors.New("offline") }
func (errorBlobs) WriteAtomic(context.Context, string, []byte, fs.FileMode) error {
	return errors.New("offline")
}
func (errorBlobs) List(context.Context, string) ([]string, error) { return nil, nil }

func TestEncryptedKeyStoreErrors(t *testing.T) {
	if _, err := encrypt([]byte("x"), "short"); err == nil {
		t.Fatal("short secret accepted")
	}
	if _, err := decrypt([]byte("not-json"), testSecret); err == nil {
		t.Fatal("corrupt payload accepted")
	}
	store := &Encrypted{Blobs: errorBlobs{}, Key: "key", Secret: testSecret}
	if _, err := store.Active(context.Background(), "issuer"); err == nil {
		t.Fatal("read error hidden")
	}
}
