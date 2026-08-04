package apxtrace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// Redactor hashes sensitive header values to a short SHA256 prefix.
// This preserves "same value across requests" signal without leaking secrets.
type Redactor struct {
	sensitive map[string]struct{}
}

// DefaultRedactor returns a Redactor with Approximated's standard
// sensitive-header list.
func DefaultRedactor() *Redactor {
	return NewRedactor([]string{
		"authorization",
		"cookie",
		"set-cookie",
		"x-api-key",
		"api-key",
		"apx-internal-key",
		"proxy-authorization",
		"x-apx-debug-trace",
	})
}

func NewRedactor(names []string) *Redactor {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[strings.ToLower(n)] = struct{}{}
	}
	return &Redactor{sensitive: m}
}

// RedactHeaders returns a new http.Header with sensitive values replaced by
// their SHA256 prefix. Non-sensitive values are copied unchanged.
func (r *Redactor) RedactHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		if _, sensitive := r.sensitive[strings.ToLower(k)]; sensitive {
			redacted := make([]string, len(vs))
			for i, v := range vs {
				redacted[i] = hashValue(v)
			}
			out[k] = redacted
		} else {
			cp := make([]string, len(vs))
			copy(cp, vs)
			out[k] = cp
		}
	}
	return out
}

// redactValues returns a copy of vs with each value hashed if the header
// name is in the sensitive set, otherwise copied unchanged.
func (r *Redactor) redactValues(name string, vs []string) []string {
	out := make([]string, len(vs))
	if _, sensitive := r.sensitive[strings.ToLower(name)]; sensitive {
		for i, v := range vs {
			out[i] = hashValue(v)
		}
	} else {
		copy(out, vs)
	}
	return out
}

func hashValue(v string) string {
	sum := sha256.Sum256([]byte(v))
	return fmt.Sprintf("<sha256:%s>", hex.EncodeToString(sum[:6]))
}
