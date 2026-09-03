package httpserver

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/laibulle/robine-id/internal/domain"
)

const sessionCookie = "robine_id_session"

type browserSession struct {
	CSRF           string                       `json:"csrf"`
	SessionID      string                       `json:"session_id,omitempty"`
	Subject        string                       `json:"subject,omitempty"`
	AuthTime       time.Time                    `json:"auth_time,omitempty"`
	Pending        *domain.AuthorizationRequest `json:"pending,omitempty"`
	LogoutReturnTo string                       `json:"logout_return_to,omitempty"`
	ReturnTo       string                       `json:"return_to,omitempty"`
}

type sessionCodec struct {
	aead   cipher.AEAD
	secure bool
}

func newSessionCodec(secret string, secure bool) (*sessionCodec, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("SESSION_SECRET must contain at least 32 characters")
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sessionCodec{aead: aead, secure: secure}, nil
}

func randomString() (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (c *sessionCodec) read(request *http.Request) browserSession {
	cookie, err := request.Cookie(sessionCookie)
	if err != nil {
		return c.fresh()
	}
	encoded, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(encoded) < c.aead.NonceSize() {
		return c.fresh()
	}
	nonce, sealed := encoded[:c.aead.NonceSize()], encoded[c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, sealed, []byte(sessionCookie))
	if err != nil {
		return c.fresh()
	}
	var session browserSession
	if json.Unmarshal(plain, &session) != nil || session.CSRF == "" {
		return c.fresh()
	}
	return session
}

func (c *sessionCodec) fresh() browserSession {
	csrf, _ := randomString()
	return browserSession{CSRF: csrf}
}

func (c *sessionCodec) write(writer http.ResponseWriter, session browserSession) error {
	plain, err := json.Marshal(session)
	if err != nil {
		return err
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	sealed := c.aead.Seal(nonce, nonce, plain, []byte(sessionCookie))
	http.SetCookie(writer, &http.Cookie{Name: sessionCookie, Value: base64.RawURLEncoding.EncodeToString(sealed), Path: "/", HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteLaxMode, MaxAge: 28800})
	return nil
}

func (c *sessionCodec) clear(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}
