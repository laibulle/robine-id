package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"sync"

	"github.com/laibulle/robine-id/internal/domain"
	"github.com/laibulle/robine-id/internal/ports"
)

type Blob struct {
	Blobs ports.BlobStore
	Key   string
	mu    sync.Mutex
}

func (b *Blob) load(ctx context.Context) (map[string]domain.User, error) {
	data, err := b.Blobs.Read(ctx, b.Key)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]domain.User{}, nil
	}
	if err != nil {
		return nil, err
	}
	var users map[string]domain.User
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (b *Blob) Get(ctx context.Context, id string) (domain.User, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	users, err := b.load(ctx)
	if err != nil {
		return domain.User{}, err
	}
	user, ok := users[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return user, nil
}

func (b *Blob) Save(ctx context.Context, user domain.User) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	users, err := b.load(ctx)
	if err != nil {
		return err
	}
	users[user.ID] = user
	data, err := json.Marshal(users)
	if err != nil {
		return err
	}
	return b.Blobs.WriteAtomic(ctx, b.Key, data, 0o600)
}
