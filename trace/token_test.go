package apxtrace

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func mintToken(t *testing.T, secret, payload string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestValidateToken_RoundTrip(t *testing.T) {
	secret := "s3cret"
	payload := `{"dr_id":"abc-123","vhost_id":42,"exp":9999999999}`
	tok := mintToken(t, secret, payload)

	p, err := ValidateToken(tok, secret)
	require.NoError(t, err)
	require.Equal(t, "abc-123", p.DebugRequestID)
	require.Equal(t, int64(42), p.VhostID)
}

func TestValidateToken_SignTokenRoundTrip(t *testing.T) {
	secret := "rotate-me"
	payload := TokenPayload{DebugRequestID: "dr-1", VhostID: 7, Exp: time.Now().Add(time.Hour).Unix()}
	tok, err := SignToken(payload, secret)
	require.NoError(t, err)

	p, err := ValidateToken(tok, secret)
	require.NoError(t, err)
	require.Equal(t, payload, *p)
}

func TestValidateToken_WrongSecret(t *testing.T) {
	payload := `{"dr_id":"x","vhost_id":1,"exp":9999999999}`
	tok := mintToken(t, "real-secret", payload)
	_, err := ValidateToken(tok, "different-secret")
	require.ErrorIs(t, err, ErrInvalidSignature)
}

func TestValidateToken_Expired(t *testing.T) {
	secret := "s"
	payload := `{"dr_id":"x","vhost_id":1,"exp":1}` // epoch 1970 — definitely expired
	tok := mintToken(t, secret, payload)
	_, err := ValidateToken(tok, secret)
	require.ErrorIs(t, err, ErrExpiredToken)
}

func TestValidateToken_MalformedNoDot(t *testing.T) {
	_, err := ValidateToken("no-dot-here", "s")
	require.ErrorIs(t, err, ErrMalformedToken)
}

func TestValidateToken_MalformedTooManyDots(t *testing.T) {
	_, err := ValidateToken("a.b.c", "s")
	require.ErrorIs(t, err, ErrMalformedToken)
}

func TestValidateToken_MalformedEmptyHalves(t *testing.T) {
	_, err := ValidateToken(".sig", "s")
	require.ErrorIs(t, err, ErrMalformedToken)
	_, err = ValidateToken("payload.", "s")
	require.ErrorIs(t, err, ErrMalformedToken)
}

func TestValidateToken_MalformedBadBase64(t *testing.T) {
	_, err := ValidateToken("!!!.!!!", "s")
	require.ErrorIs(t, err, ErrMalformedToken)
}

func TestValidateToken_MalformedBadJSON(t *testing.T) {
	secret := "s"
	bad := "not-json"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(bad))
	tok := base64.RawURLEncoding.EncodeToString([]byte(bad)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	_, err := ValidateToken(tok, secret)
	require.ErrorIs(t, err, ErrMalformedToken)
}

func TestValidateToken_MalformedMissingExp(t *testing.T) {
	secret := "s"
	payload := `{"dr_id":"x","vhost_id":1}`
	tok := mintToken(t, secret, payload)
	_, err := ValidateToken(tok, secret)
	require.ErrorIs(t, err, ErrMalformedToken)
}

func TestValidateToken_MalformedMissingDrID(t *testing.T) {
	secret := "s"
	payload := `{"dr_id":"","vhost_id":1,"exp":9999999999}`
	tok := mintToken(t, secret, payload)
	_, err := ValidateToken(tok, secret)
	require.ErrorIs(t, err, ErrMalformedToken)
}

func TestValidateToken_EncodingContainsNoPaddingNoStdChars(t *testing.T) {
	// Defensive: RawURL encoding must not emit '=' or '+' or '/'.
	secret := "s"
	payload := TokenPayload{DebugRequestID: "abc/+=", VhostID: 12, Exp: time.Now().Add(time.Hour).Unix()}
	tok, err := SignToken(payload, secret)
	require.NoError(t, err)
	require.False(t, strings.ContainsAny(tok, "=+/"), "RawURL encoding should not emit = + /")
}

// sanity check that error sentinels are unique
func TestValidateToken_ErrorSentinelsDistinct(t *testing.T) {
	require.False(t, errors.Is(ErrMalformedToken, ErrInvalidSignature))
	require.False(t, errors.Is(ErrInvalidSignature, ErrExpiredToken))
	require.False(t, errors.Is(ErrExpiredToken, ErrMalformedToken))
}
