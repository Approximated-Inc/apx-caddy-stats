package apxtrace

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TokenPayload is the claims JSON signed into a trace token.
// Keep in sync with the app-side signer.
type TokenPayload struct {
	DebugRequestID string `json:"dr_id"`
	VhostID        int64  `json:"vhost_id"`
	Exp            int64  `json:"exp"`
}

// Token validation error sentinels. The handler treats all as "invalid_token".
var (
	ErrMalformedToken   = errors.New("apx-caddy-trace: malformed trace token")
	ErrInvalidSignature = errors.New("apx-caddy-trace: invalid trace token signature")
	ErrExpiredToken     = errors.New("apx-caddy-trace: expired trace token")
)

// ValidateToken verifies an HMAC-SHA256 signed trace token and returns its
// payload. Token format: base64url(payload_json) + "." + base64url(hmac).
// Base64 encoding is RawURL (no padding).
func ValidateToken(token, secret string) (*TokenPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, ErrMalformedToken
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %v", ErrMalformedToken, err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: decode signature: %v", ErrMalformedToken, err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payloadBytes)
	expected := mac.Sum(nil)
	if !hmac.Equal(sigBytes, expected) {
		return nil, ErrInvalidSignature
	}

	var p TokenPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, fmt.Errorf("%w: parse payload: %v", ErrMalformedToken, err)
	}
	if p.Exp == 0 {
		return nil, fmt.Errorf("%w: missing exp", ErrMalformedToken)
	}
	if time.Now().Unix() > p.Exp {
		return nil, ErrExpiredToken
	}
	if p.DebugRequestID == "" {
		return nil, fmt.Errorf("%w: missing dr_id", ErrMalformedToken)
	}
	return &p, nil
}

// SignToken produces a trace token for the given payload. Exposed mainly for
// test code; real production signing happens on the app side in Elixir.
func SignToken(p TokenPayload, secret string) (string, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
