package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEnvironmentAndLogLevel(t *testing.T) {
	t.Setenv("VALUE", "configured")
	if env("VALUE", "default") != "configured" || env("MISSING", "default") != "default" {
		t.Fatal("env")
	}
	for _, value := range []string{"debug", "info", "warning", "warn", "error", "unknown"} {
		_ = logLevel(value)
	}
}

func TestBuildLocalBlobStore(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ROBINE_ID_BLOB_STORE", "local")
	t.Setenv("ROBINE_ID_CONFIG", filepath.Join(root, "custom.json"))
	t.Setenv("ROBINE_ID_APPLICATIONS_PREFIX", "")
	store, key, apps, err := buildBlobStore(context.Background())
	if err != nil || store == nil || key != "custom.json" || apps != "applications" {
		t.Fatalf("%T %s %s %v", store, key, apps, err)
	}
	t.Setenv("ROBINE_ID_BLOB_STORE", "invalid")
	if _, _, _, err := buildBlobStore(context.Background()); err == nil {
		t.Fatal("invalid driver accepted")
	}
	t.Setenv("ROBINE_ID_BLOB_STORE", "s3")
	t.Setenv("ROBINE_ID_S3_BUCKET", "")
	if _, _, _, err := buildBlobStore(context.Background()); err == nil {
		t.Fatal("missing bucket accepted")
	}
	t.Setenv("ROBINE_ID_BLOB_STORE", "local")
	t.Setenv("ROBINE_ID_STATE_BLOB_STORE", "local")
	t.Setenv("ROBINE_ID_STATE_ROOT", root)
	if store, err := buildStateBlobStore(context.Background(), nil); err != nil || store == nil {
		t.Fatal(err)
	}
	t.Setenv("ROBINE_ID_STATE_BLOB_STORE", "invalid")
	if _, err := buildStateBlobStore(context.Background(), nil); err == nil {
		t.Fatal("invalid state driver accepted")
	}
	t.Setenv("ROBINE_ID_STATE_BLOB_STORE", "s3")
	t.Setenv("ROBINE_ID_S3_BUCKET", "")
	if _, err := buildStateBlobStore(context.Background(), nil); err == nil {
		t.Fatal("missing state bucket accepted")
	}
}

func TestRunCanStartAndShutdown(t *testing.T) {
	root := t.TempDir()
	config := `{"schema_version":1,"issuers":[{"id":"default","url":"https://id.example/default","token_policy":{}}],"users":[],"claims":{},"branding":{},"authentication":{},"storage":{},"telemetry":{},"reconciliation":{}}`
	if err := os.WriteFile(filepath.Join(root, "robine_id.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "applications"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ROBINE_ID_BLOB_STORE", "local")
	t.Setenv("ROBINE_ID_STORAGE_ROOT", root)
	t.Setenv("ROBINE_ID_CONFIG_KEY", "robine_id.json")
	t.Setenv("ROBINE_ID_APPLICATIONS_PREFIX", "applications")
	t.Setenv("SECRET_KEY_BASE", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz")
	t.Setenv("ROBINE_ID_SECURE_COOKIES", "false")
	t.Setenv("PORT", "0")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx); err != nil {
		t.Fatal(err)
	}
}
