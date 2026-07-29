package apxchallenge

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"
)

// New HMAC domains, distinct from chal/pass in cookie.go so a form
// challenge/token can never cross-validate as an interstitial token.
const (
	formChallengeDomain = "formchal"
	formTokenDomain     = "formtok"
)

// FormChallengePayload is the signed body of an issued form PoW challenge.
type FormChallengePayload struct {
	Exp    int64  `json:"e"`
	Nonce  string `json:"n"`
	Prefix string `json:"p"`
	Diff   int    `json:"d"`
}

// FormTokenPayload is the signed body of a minted form-protection token.
type FormTokenPayload struct {
	Exp    int64  `json:"e"`
	Nonce  string `json:"n"`
	Prefix string `json:"p"`
	Host   string `json:"h"`
}

func randNonce() string {
	nb := make([]byte, 12)
	_, _ = rand.Read(nb)
	return base64.RawURLEncoding.EncodeToString(nb)
}

// IssueFormChallenge mints a signed PoW challenge bound to the client prefix,
// carrying the difficulty the widget must solve.
func IssueFormChallenge(secret, ip string, difficulty int, exp time.Time) string {
	pref, _ := clientPrefix(ip)
	body, _ := json.Marshal(FormChallengePayload{
		Exp: exp.Unix(), Nonce: randNonce(), Prefix: pref, Diff: difficulty,
	})
	return encodeSigned(secret, formChallengeDomain, body)
}

// VerifyFormChallenge checks signature, expiry, and prefix match.
func VerifyFormChallenge(secret, token, ip string) (FormChallengePayload, error) {
	body, err := splitVerify(secret, formChallengeDomain, token)
	if err != nil {
		return FormChallengePayload{}, err
	}
	var p FormChallengePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return FormChallengePayload{}, errInvalid
	}
	if time.Now().Unix() > p.Exp {
		return FormChallengePayload{}, errInvalid
	}
	pref, ok := clientPrefix(ip)
	if !ok || p.Prefix != pref {
		return FormChallengePayload{}, errInvalid
	}
	return p, nil
}

// IssueFormToken mints the token the widget injects into the form. Bound to
// client prefix AND host so a token minted for one site can't clear another.
func IssueFormToken(secret, ip, host, nonce string, exp time.Time) string {
	pref, _ := clientPrefix(ip)
	body, _ := json.Marshal(FormTokenPayload{
		Exp: exp.Unix(), Nonce: nonce, Prefix: pref, Host: host,
	})
	return encodeSigned(secret, formTokenDomain, body)
}

// VerifyFormToken checks signature, expiry, prefix, and host.
func VerifyFormToken(secret, token, ip, host string) (FormTokenPayload, error) {
	body, err := splitVerify(secret, formTokenDomain, token)
	if err != nil {
		return FormTokenPayload{}, err
	}
	var p FormTokenPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return FormTokenPayload{}, errInvalid
	}
	if time.Now().Unix() > p.Exp {
		return FormTokenPayload{}, errInvalid
	}
	pref, ok := clientPrefix(ip)
	if !ok || p.Prefix != pref || p.Host != host {
		return FormTokenPayload{}, errInvalid
	}
	return p, nil
}
