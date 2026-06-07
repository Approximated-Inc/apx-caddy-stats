package apxchallenge

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const secret = "unit-secret"

func TestClientPrefix(t *testing.T) {
	require.Equal(t, "203.0.113.0/24", clientPrefix("203.0.113.45"))
	require.Equal(t, "203.0.113.0/24", clientPrefix("203.0.113.200"))
	require.Equal(t, "2001:db8:1:2::/64", clientPrefix("2001:db8:1:2:3:4:5:6"))
}

func TestChallengeTokenRoundTrip(t *testing.T) {
	tok := IssueChallenge(secret, "203.0.113.5", "/dashboard", time.Now().Add(2*time.Minute))
	p, err := VerifyChallenge(secret, tok, "203.0.113.250") // same /24
	require.NoError(t, err)
	require.Equal(t, "/dashboard", p.Ret)
	require.Equal(t, "203.0.113.0/24", p.Prefix)
}

func TestChallengeTokenRejectsTamper(t *testing.T) {
	tok := IssueChallenge(secret, "203.0.113.5", "/x", time.Now().Add(2*time.Minute))
	_, err := VerifyChallenge(secret, tok+"x", "203.0.113.5")
	require.Error(t, err)
	_, err = VerifyChallenge("other-secret", tok, "203.0.113.5")
	require.Error(t, err)
}

func TestChallengeTokenRejectsExpiredAndWrongPrefix(t *testing.T) {
	expired := IssueChallenge(secret, "203.0.113.5", "/x", time.Now().Add(-time.Second))
	_, err := VerifyChallenge(secret, expired, "203.0.113.5")
	require.Error(t, err)

	tok := IssueChallenge(secret, "203.0.113.5", "/x", time.Now().Add(2*time.Minute))
	_, err = VerifyChallenge(secret, tok, "198.51.100.5") // different /24
	require.Error(t, err)
}

func TestCookieRoundTrip(t *testing.T) {
	c := IssueCookie(secret, "203.0.113.5", time.Now().Add(10*time.Minute))
	require.True(t, VerifyCookie(secret, c, "203.0.113.99"))
	require.False(t, VerifyCookie(secret, c, "198.51.100.5"))
	require.False(t, VerifyCookie("nope", c, "203.0.113.5"))
}

func TestCookieRejectsExpired(t *testing.T) {
	c := IssueCookie(secret, "203.0.113.5", time.Now().Add(-time.Second))
	require.False(t, VerifyCookie(secret, c, "203.0.113.5"))
}
