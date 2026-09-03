package ports

import (
	"context"
	"io/fs"
	"time"

	"github.com/laibulle/robine-id/internal/domain"
)

// BlobStore isolates configuration and key persistence from local files and S3.
type BlobStore interface {
	Read(context.Context, string) ([]byte, error)
	WriteAtomic(context.Context, string, []byte, fs.FileMode) error
	List(context.Context, string) ([]string, error)
}

type ConfigurationRepository interface {
	Active(context.Context) (*domain.Snapshot, error)
}

type AccountRepository interface {
	Get(context.Context, string) (domain.User, error)
	Save(context.Context, domain.User) error
}

type AuthorizationCodeStore interface {
	Issue(context.Context, domain.AuthorizationGrant) (string, error)
	Consume(context.Context, string) (domain.AuthorizationGrant, error)
	MarkExchanged(context.Context, string, string) error
}

type AccessTokenStore interface {
	Issue(context.Context, domain.AccessGrant) (string, error)
	Get(context.Context, string) (domain.AccessGrant, error)
	Revoke(context.Context, string) error
}

type SessionRegistry interface {
	Start(context.Context, string, time.Time, int) (domain.Session, error)
	Validate(context.Context, string, time.Time, domain.SessionPolicy) (domain.Session, error)
	End(context.Context, string) error
}

type RateLimiter interface {
	Allow(context.Context, string, int, time.Duration, time.Time) (bool, time.Duration)
}

type KeyStore interface {
	Active(context.Context, string) (domain.SigningKey, error)
	All(context.Context, string) ([]domain.SigningKey, error)
	Rotate(context.Context, string, string) (domain.SigningKey, error)
}

type PasswordHasher interface {
	Compare(string, string) bool
	Hash(string) (string, error)
}

type Clock interface{ Now() time.Time }

type AuditSink interface {
	Record(context.Context, string, map[string]string)
}
