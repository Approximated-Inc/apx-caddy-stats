package apxchallenge

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const secret = "unit-secret"

func TestClientPrefix(t *testing.T) {
	p, ok := clientPrefix("203.0.113.45")
	require.True(t, ok)
	require.Equal(t, "203.0.113.0/24", p)

	p, ok = clientPrefix("203.0.113.200")
	require.True(t, ok)
	require.Equal(t, "203.0.113.0/24", p)

	p, ok = clientPrefix("2001:db8:1:2:3:4:5:6")
	require.True(t, ok)
	require.Equal(t, "2001:db8:1:2::/64", p)

	_, ok = clientPrefix("not-an-ip")
	require.False(t, ok)
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

func TestCrossProtocolTokenRejected(t *testing.T) {
	chal := IssueChallenge(secret, "203.0.113.5", "/x", time.Now().Add(2*time.Minute))
	require.False(t, VerifyCookie(secret, chal, "203.0.113.5"), "a challenge token must NOT pass as a cookie")

	cook := IssueCookie(secret, "203.0.113.5", time.Now().Add(2*time.Minute))
	_, err := VerifyChallenge(secret, cook, "203.0.113.5")
	require.Error(t, err, "a pass cookie must NOT verify as a challenge token")
}

func TestVerifyRejectsMalformedAndNoDot(t *testing.T) {
	// No dot.
	_, err := VerifyChallenge(secret, "no-dot-here", "203.0.113.5")
	require.Error(t, err)
	require.False(t, VerifyCookie(secret, "no-dot-here", "203.0.113.5"))

	// Empty token.
	_, err = VerifyChallenge(secret, "", "203.0.113.5")
	require.Error(t, err)
	require.False(t, VerifyCookie(secret, "", "203.0.113.5"))

	// Valid signature over non-JSON body → HMAC passes but unmarshal fails.
	badChal := encodeSigned(secret, challengeDomain, []byte("not-json"))
	_, err = VerifyChallenge(secret, badChal, "203.0.113.5")
	require.Error(t, err)

	badCook := encodeSigned(secret, cookieDomain, []byte("not-json"))
	require.False(t, VerifyCookie(secret, badCook, "203.0.113.5"))
}

func TestVerifyRejectsUnparseableIP(t *testing.T) {
	chal := IssueChallenge(secret, "203.0.113.5", "/x", time.Now().Add(2*time.Minute))
	_, err := VerifyChallenge(secret, chal, "not-an-ip")
	require.Error(t, err)

	cook := IssueCookie(secret, "203.0.113.5", time.Now().Add(2*time.Minute))
	require.False(t, VerifyCookie(secret, cook, "not-an-ip"))
}
