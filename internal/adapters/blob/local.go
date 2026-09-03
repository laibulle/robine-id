package blob

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Local struct{ Root string }

func (l Local) resolve(key string) (string, error) {
	if filepath.IsAbs(key) {
		return "", fmt.Errorf("blob key must be relative")
	}
	clean := filepath.Clean(key)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("blob key escapes root")
	}
	root, err := filepath.Abs(l.Root)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, clean)
	if path != root && !strings.HasPrefix(path, root+string(filepath.Separator)) {
		return "", fmt.Errorf("blob key escapes root")
	}
	return path, nil
}

func (l Local) Read(_ context.Context, key string) ([]byte, error) {
	path, err := l.resolve(key)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fs.ErrNotExist
	}
	return data, err
}

func (l Local) WriteAtomic(_ context.Context, key string, data []byte, mode fs.FileMode) error {
	path, err := l.resolve(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".robine-id-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func (l Local) List(_ context.Context, prefix string) ([]string, error) {
	path, err := l.resolve(prefix)
	if err != nil {
		return nil, err
	}
	var keys []string
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if errors.Is(walkErr, os.ErrNotExist) {
			return fs.SkipDir
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		root, _ := filepath.Abs(l.Root)
		relative, relErr := filepath.Rel(root, current)
		if relErr != nil {
			return relErr
		}
		keys = append(keys, filepath.ToSlash(relative))
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	sort.Strings(keys)
	return keys, err
}
