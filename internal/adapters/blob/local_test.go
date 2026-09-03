package blob

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLocalRoundTripAndList(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store := Local{Root: root}
	if err := store.WriteAtomic(ctx, "apps/a.json", []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteAtomic(ctx, "apps/b.json", []byte("two"), 0o640); err != nil {
		t.Fatal(err)
	}
	data, err := store.Read(ctx, "apps/a.json")
	if err != nil || string(data) != "one" {
		t.Fatalf("read: %s %v", data, err)
	}
	info, _ := os.Stat(filepath.Join(root, "apps/a.json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	keys, err := store.List(ctx, "apps")
	if err != nil || !reflect.DeepEqual(keys, []string{"apps/a.json", "apps/b.json"}) {
		t.Fatalf("list: %#v %v", keys, err)
	}
	if _, err := store.Read(ctx, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	for _, key := range []string{"../escape", "/absolute", "."} {
		if store.WriteAtomic(ctx, key, nil, 0o600) == nil {
			t.Errorf("accepted %s", key)
		}
	}
}
