package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/laibulle/robine-id/internal/adapters/accounts"
	"github.com/laibulle/robine-id/internal/adapters/blob"
	configadapter "github.com/laibulle/robine-id/internal/adapters/config"
	cryptoadapter "github.com/laibulle/robine-id/internal/adapters/crypto"
	"github.com/laibulle/robine-id/internal/adapters/httpserver"
	"github.com/laibulle/robine-id/internal/adapters/keystore"
	"github.com/laibulle/robine-id/internal/adapters/memory"
	"github.com/laibulle/robine-id/internal/adapters/observability"
	"github.com/laibulle/robine-id/internal/application"
	"github.com/laibulle/robine-id/internal/ports"
)

func main() {
	if err := run(context.Background()); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel(env("LOG_LEVEL", "info"))}))
	blobs, rootKey, applicationsPrefix, err := buildBlobStore(ctx)
	if err != nil {
		return err
	}
	reloadMilliseconds, err := strconv.Atoi(env("ROBINE_ID_RELOAD_INTERVAL", "1000"))
	if err != nil || reloadMilliseconds < 1 {
		return fmt.Errorf("ROBINE_ID_RELOAD_INTERVAL must be a positive number of milliseconds")
	}
	configuration := &configadapter.Repository{Blobs: blobs, RootKey: rootKey, ApplicationsPrefix: applicationsPrefix, ReloadInterval: time.Duration(reloadMilliseconds) * time.Millisecond}
	snapshot, err := configuration.Load(ctx)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	stateBlobs, err := buildStateBlobStore(ctx, blobs)
	if err != nil {
		return err
	}
	keyName := env("ROBINE_ID_SIGNING_KEY", "state/signing_keys.json.enc")
	secret := os.Getenv("SECRET_KEY_BASE")
	if secret == "" {
		secret = os.Getenv("SESSION_SECRET")
	}
	keys := &keystore.Encrypted{Blobs: stateBlobs, Key: keyName, Secret: secret}
	accountStore := &accounts.Blob{Blobs: stateBlobs, Key: env("ROBINE_ID_ACCOUNTS_KEY", "accounts.json")}
	provider := &application.Provider{
		Config:      configuration,
		Accounts:    accountStore,
		Codes:       memory.NewAuthorizationCodes(),
		Tokens:      memory.NewAccessTokens(),
		Sessions:    memory.NewSessions(),
		Limits:      memory.NewRateLimits(),
		Keys:        keys,
		Passwords:   cryptoadapter.Bcrypt{},
		Audit:       observability.AuditLog{Logger: logger},
		Environment: os.Getenv,
	}
	for _, issuer := range snapshot.Issuers {
		if _, err := provider.JWKS(ctx, issuer.ID); err != nil {
			return fmt.Errorf("initialize signing key for issuer %s: %w", issuer.ID, err)
		}
	}
	secure := env("ROBINE_ID_SECURE_COOKIES", "true") != "false"
	web, err := httpserver.New(provider, logger, httpserver.Options{
		SessionSecret: secret,
		SecureCookies: secure,
		Development:   env("ROBINE_ID_ENV", "production") == "development",
	})
	if err != nil {
		return err
	}
	port := env("PORT", "8080")
	server := &http.Server{Addr: ":" + port, Handler: web.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	stopContext, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errorsChannel := make(chan error, 1)
	go func() {
		logger.Info("server started", "port", port, "revision", snapshot.Fingerprint)
		errorsChannel <- server.ListenAndServe()
	}()
	select {
	case err := <-errorsChannel:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-stopContext.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

func buildStateBlobStore(ctx context.Context, configurationBlobs ports.BlobStore) (ports.BlobStore, error) {
	driver := env("ROBINE_ID_STATE_BLOB_STORE", env("ROBINE_ID_BLOB_STORE", "local"))
	switch driver {
	case "local":
		if root := os.Getenv("ROBINE_ID_STATE_ROOT"); root != "" {
			return blob.Local{Root: root}, nil
		}
		return configurationBlobs, nil
	case "s3":
		bucket := os.Getenv("ROBINE_ID_S3_BUCKET")
		if bucket == "" {
			return nil, fmt.Errorf("ROBINE_ID_S3_BUCKET is required")
		}
		region := env("AWS_REGION", "eu-west-1")
		sdkConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return nil, err
		}
		client := s3.NewFromConfig(sdkConfig, func(options *s3.Options) {
			if endpoint := os.Getenv("ROBINE_ID_S3_ENDPOINT"); endpoint != "" {
				options.BaseEndpoint = &endpoint
				options.UsePathStyle = true
			}
		})
		return blob.S3{Client: client, Bucket: bucket, Prefix: os.Getenv("ROBINE_ID_S3_STATE_PREFIX")}, nil
	default:
		return nil, fmt.Errorf("ROBINE_ID_STATE_BLOB_STORE must be local or s3")
	}
}

func buildBlobStore(ctx context.Context) (ports.BlobStore, string, string, error) {
	rootKey := env("ROBINE_ID_CONFIG_KEY", "robine_id.json")
	applications := env("ROBINE_ID_APPLICATIONS_PREFIX", configadapter.ApplicationPrefix(rootKey))
	switch env("ROBINE_ID_BLOB_STORE", "local") {
	case "local":
		root := env("ROBINE_ID_STORAGE_ROOT", "config")
		if explicit := os.Getenv("ROBINE_ID_CONFIG"); explicit != "" {
			absolute, err := filepath.Abs(explicit)
			if err != nil {
				return nil, "", "", err
			}
			root, rootKey = filepath.Dir(absolute), filepath.Base(absolute)
			if os.Getenv("ROBINE_ID_APPLICATIONS_PREFIX") == "" {
				applications = "applications"
			}
		}
		return blob.Local{Root: root}, rootKey, applications, nil
	case "s3":
		bucket := os.Getenv("ROBINE_ID_S3_BUCKET")
		if bucket == "" {
			return nil, "", "", fmt.Errorf("ROBINE_ID_S3_BUCKET is required")
		}
		region := env("AWS_REGION", "eu-west-1")
		sdkConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return nil, "", "", err
		}
		client := s3.NewFromConfig(sdkConfig, func(options *s3.Options) {
			if endpoint := os.Getenv("ROBINE_ID_S3_ENDPOINT"); endpoint != "" {
				options.BaseEndpoint = &endpoint
				options.UsePathStyle = true
			}
		})
		return blob.S3{Client: client, Bucket: bucket, Prefix: os.Getenv("ROBINE_ID_S3_PREFIX")}, rootKey, applications, nil
	default:
		return nil, "", "", fmt.Errorf("ROBINE_ID_BLOB_STORE must be local or s3")
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func logLevel(value string) slog.Level {
	switch value {
	case "debug":
		return slog.LevelDebug
	case "warning", "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
