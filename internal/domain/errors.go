package domain

import "fmt"

type ProtocolError struct {
	Code            string
	Description     string
	Status          int
	TrustedRedirect bool
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func NewProtocolError(code, description string) *ProtocolError {
	return &ProtocolError{Code: code, Description: description, Status: 400}
}

var (
	ErrNotFound    = fmt.Errorf("not found")
	ErrAlreadyUsed = fmt.Errorf("already used")
)

type ValidationError map[string]string

func (e ValidationError) Error() string { return "validation failed" }

type AuthorizationCodeReuseError struct{ AccessToken string }

func (e *AuthorizationCodeReuseError) Error() string { return "authorization code already used" }
func (e *AuthorizationCodeReuseError) Unwrap() error { return ErrAlreadyUsed }
