package keystore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"sync"

	"github.com/laibulle/robine-id/internal/domain"
	"github.com/laibulle/robine-id/internal/ports"
)

const envelopeVersion = 1

type envelope struct {
	Version int    `json:"version"`
	Nonce   string `json:"nonce"`
	Data    string `json:"data"`
}

type payload struct {
	Keys map[string][]domain.SigningKey `json:"keys"`
}

type Encrypted struct {
	Blobs  ports.BlobStore
	Key    string
	Secret string
	mu     sync.Mutex
	loaded bool
	keys   map[string][]domain.SigningKey
}

func (s *Encrypted) ensureLoaded(ctx context.Context) error {
	if s.loaded {
		return nil
	}
	s.keys = map[string][]domain.SigningKey{}
	data, err := s.Blobs.Read(ctx, s.Key)
	if err != nil {
		if err == fs.ErrNotExist {
			s.loaded = true
			return nil
		}
		return err
	}
	plain, err := decrypt(data, s.Secret)
	if err != nil {
		return fmt.Errorf("decrypt signing keys: %w", err)
	}
	var stored payload
	if err := json.Unmarshal(plain, &stored); err != nil {
		return fmt.Errorf("decode signing keys: %w", err)
	}
	if stored.Keys != nil {
		s.keys = stored.Keys
	}
	s.loaded = true
	return nil
}

func (s *Encrypted) Active(ctx context.Context, issuer string) (domain.SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoaded(ctx); err != nil {
		return domain.SigningKey{}, err
	}
	for _, key := range s.keys[issuer] {
		if key.Active {
			return key, nil
		}
	}
	return domain.SigningKey{}, domain.ErrNotFound
}

func (s *Encrypted) All(ctx context.Context, issuer string) ([]domain.SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	result := append([]domain.SigningKey(nil), s.keys[issuer]...)
	return result, nil
}

func (s *Encrypted) Rotate(ctx context.Context, issuer, rotationID string) (domain.SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoaded(ctx); err != nil {
		return domain.SigningKey{}, err
	}
	for _, key := range s.keys[issuer] {
		if key.Active && key.ID == rotationID {
			return key, nil
		}
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return domain.SigningKey{}, err
	}
	privateDER := x509.MarshalPKCS1PrivateKey(private)
	key := domain.SigningKey{ID: rotationID, Active: true, PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateDER})}
	existing := s.keys[issuer]
	for index := range existing {
		existing[index].Active = false
	}
	s.keys[issuer] = append(existing, key)
	encoded, err := json.Marshal(payload{Keys: s.keys})
	if err != nil {
		return domain.SigningKey{}, err
	}
	sealed, err := encrypt(encoded, s.Secret)
	if err != nil {
		return domain.SigningKey{}, err
	}
	if err := s.Blobs.WriteAtomic(ctx, s.Key, sealed, 0o600); err != nil {
		return domain.SigningKey{}, err
	}
	return key, nil
}

func encrypt(plain []byte, secret string) ([]byte, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("key-store secret must contain at least 32 characters")
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plain, []byte("robine-id-signing-keys-v1"))
	return json.Marshal(envelope{Version: envelopeVersion, Nonce: base64.RawStdEncoding.EncodeToString(nonce), Data: base64.RawStdEncoding.EncodeToString(sealed)})
}

func decrypt(data []byte, secret string) ([]byte, error) {
	var wrapped envelope
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.Version != envelopeVersion {
		return nil, fmt.Errorf("unsupported envelope version")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(wrapped.Nonce)
	if err != nil {
		return nil, err
	}
	sealed, err := base64.RawStdEncoding.DecodeString(wrapped.Data)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, sealed, []byte("robine-id-signing-keys-v1"))
}
