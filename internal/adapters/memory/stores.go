package memory

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"

	"github.com/laibulle/robine-id/internal/domain"
)

type codeRecord struct {
	grant       domain.AuthorizationGrant
	used        bool
	accessToken string
}

type AuthorizationCodes struct {
	mu     sync.Mutex
	values map[[32]byte]codeRecord
}

func NewAuthorizationCodes() *AuthorizationCodes {
	return &AuthorizationCodes{values: make(map[[32]byte]codeRecord)}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *AuthorizationCodes) Issue(_ context.Context, grant domain.AuthorizationGrant) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[sha256.Sum256([]byte(token))] = codeRecord{grant: grant}
	return token, nil
}

func (s *AuthorizationCodes) Consume(_ context.Context, token string) (domain.AuthorizationGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.values[sha256.Sum256([]byte(token))]
	if !ok {
		return domain.AuthorizationGrant{}, domain.ErrNotFound
	}
	if record.used {
		return domain.AuthorizationGrant{}, &domain.AuthorizationCodeReuseError{AccessToken: record.accessToken}
	}
	record.used = true
	s.values[sha256.Sum256([]byte(token))] = record
	return record.grant, nil
}

func (s *AuthorizationCodes) MarkExchanged(_ context.Context, token, accessToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := sha256.Sum256([]byte(token))
	record, ok := s.values[h]
	if !ok {
		return domain.ErrNotFound
	}
	record.accessToken = accessToken
	s.values[h] = record
	return nil
}

type AccessTokens struct {
	mu     sync.RWMutex
	values map[[32]byte]domain.AccessGrant
}

func NewAccessTokens() *AccessTokens {
	return &AccessTokens{values: make(map[[32]byte]domain.AccessGrant)}
}

func (s *AccessTokens) Issue(_ context.Context, grant domain.AccessGrant) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.values[sha256.Sum256([]byte(token))] = grant
	s.mu.Unlock()
	return token, nil
}

func (s *AccessTokens) Get(_ context.Context, token string) (domain.AccessGrant, error) {
	s.mu.RLock()
	grant, ok := s.values[sha256.Sum256([]byte(token))]
	s.mu.RUnlock()
	if !ok {
		return domain.AccessGrant{}, domain.ErrNotFound
	}
	return grant, nil
}

func (s *AccessTokens) Revoke(_ context.Context, token string) error {
	s.mu.Lock()
	delete(s.values, sha256.Sum256([]byte(token)))
	s.mu.Unlock()
	return nil
}

type Sessions struct {
	mu        sync.Mutex
	values    map[string]domain.Session
	bySubject map[string][]string
}

func NewSessions() *Sessions {
	return &Sessions{values: map[string]domain.Session{}, bySubject: map[string][]string{}}
}

func (s *Sessions) Start(_ context.Context, subject string, now time.Time, maximum int) (domain.Session, error) {
	id, err := randomToken()
	if err != nil {
		return domain.Session{}, err
	}
	session := domain.Session{ID: id, Subject: subject, StartedAt: now, LastSeenAt: now}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := append(s.bySubject[subject], id)
	if maximum > 0 && len(ids) > maximum {
		for _, old := range ids[:len(ids)-maximum] {
			delete(s.values, old)
		}
		ids = ids[len(ids)-maximum:]
	}
	s.values[id] = session
	s.bySubject[subject] = ids
	return session, nil
}

func (s *Sessions) Validate(_ context.Context, id string, now time.Time, policy domain.SessionPolicy) (domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.values[id]
	if !ok || now.Sub(session.StartedAt) >= time.Duration(policy.AbsoluteTimeout)*time.Second || now.Sub(session.LastSeenAt) >= time.Duration(policy.IdleTimeout)*time.Second {
		delete(s.values, id)
		return domain.Session{}, domain.ErrNotFound
	}
	session.LastSeenAt = now
	s.values[id] = session
	return session, nil
}

func (s *Sessions) End(_ context.Context, id string) error {
	s.mu.Lock()
	delete(s.values, id)
	s.mu.Unlock()
	return nil
}

type RateLimits struct {
	mu      sync.Mutex
	entries map[string][]time.Time
}

func NewRateLimits() *RateLimits { return &RateLimits{entries: map[string][]time.Time{}} }

func (r *RateLimits) Allow(_ context.Context, key string, attempts int, window time.Duration, now time.Time) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-window)
	kept := r.entries[key][:0]
	for _, at := range r.entries[key] {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	if len(kept) >= attempts {
		r.entries[key] = kept
		return false, kept[0].Add(window).Sub(now)
	}
	r.entries[key] = append(kept, now)
	return true, 0
}
