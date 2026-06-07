package apxchallenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"time"
)

// CookieName is the pass cookie set after a solved challenge.
const CookieName = "apx-challenge"

// Domain-separation labels mixed into the HMAC input so a challenge token can
// never validate as a pass cookie (and vice versa).
const (
	challengeDomain = "chal"
	cookieDomain    = "pass"
)

// ChallengePayload is the signed body of an issued PoW challenge token.
type ChallengePayload struct {
	Exp    int64  `json:"e"`
	Nonce  string `json:"n"`
	Prefix string `json:"p"`
	Ret    string `json:"r"`
}

type cookiePayload struct {
	Exp    int64  `json:"e"`
	Prefix string `json:"p"`
}

var errInvalid = errors.New("apx_challenge: invalid or expired token")

// clientPrefix returns the /24 (v4) or /64 (v6) network of ip as a string.
// The bool is false when ip is unparseable, so callers can reject rather than
// match unparseable IPs against each other.
func clientPrefix(ip string) (string, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	if v4 := parsed.To4(); v4 != nil {
		mask := net.CIDRMask(24, 32)
		return (&net.IPNet{IP: v4.Mask(mask), Mask: mask}).String(), true
	}
	mask := net.CIDRMask(64, 128)
	return (&net.IPNet{IP: parsed.Mask(mask), Mask: mask}).String(), true
}

func sign(secret, domain string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(domain))
	m.Write([]byte{0}) // unambiguous separator between domain and body
	m.Write(body)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func encodeSigned(secret, domain string, body []byte) string {
	return base64.RawURLEncoding.EncodeToString(body) + "." + sign(secret, domain, body)
}

// splitVerify returns the decoded body iff the signature matches (constant-time).
func splitVerify(secret, domain, token string) ([]byte, error) {
	dot := -1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 {
		return nil, errInvalid
	}
	body, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		return nil, errInvalid
	}
	want := sign(secret, domain, body)
	if !hmac.Equal([]byte(want), []byte(token[dot+1:])) {
		return nil, errInvalid
	}
	return body, nil
}

// IssueChallenge mints a signed PoW challenge token bound to the client prefix.
func IssueChallenge(secret, ip, ret string, exp time.Time) string {
	nb := make([]byte, 12)
	_, _ = rand.Read(nb)
	pref, _ := clientPrefix(ip)
	body, _ := json.Marshal(ChallengePayload{
		Exp:    exp.Unix(),
		Nonce:  base64.RawURLEncoding.EncodeToString(nb),
		Prefix: pref,
		Ret:    ret,
	})
	return encodeSigned(secret, challengeDomain, body)
}

// VerifyChallenge checks signature, expiry, and prefix match.
func VerifyChallenge(secret, token, ip string) (ChallengePayload, error) {
	body, err := splitVerify(secret, challengeDomain, token)
	if err != nil {
		return ChallengePayload{}, err
	}
	var p ChallengePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return ChallengePayload{}, errInvalid
	}
	if time.Now().Unix() > p.Exp {
		return ChallengePayload{}, errInvalid
	}
	pref, ok := clientPrefix(ip)
	if !ok || p.Prefix != pref {
		return ChallengePayload{}, errInvalid
	}
	return p, nil
}

// IssueCookie mints the pass cookie value (HMAC over {exp, prefix}).
func IssueCookie(secret, ip string, exp time.Time) string {
	pref, _ := clientPrefix(ip)
	body, _ := json.Marshal(cookiePayload{Exp: exp.Unix(), Prefix: pref})
	return encodeSigned(secret, cookieDomain, body)
}

// VerifyCookie reports whether the cookie is well-signed, unexpired, and bound
// to the requester's current prefix.
func VerifyCookie(secret, cookie, ip string) bool {
	body, err := splitVerify(secret, cookieDomain, cookie)
	if err != nil {
		return false
	}
	var p cookiePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return false
	}
	if time.Now().Unix() > p.Exp {
		return false
	}
	pref, ok := clientPrefix(ip)
	return ok && p.Prefix == pref
}
