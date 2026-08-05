package apxstats

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unsafe"
)

// newReq builds a GET request with the given RemoteAddr and headers.
// headers is a flat list of key, value pairs.
func newReq(remoteAddr string, headers ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return r
}

func TestSecurityClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    []string
		want       string
	}{
		{
			name:       "ipv4 with port, no headers",
			remoteAddr: "203.0.113.5:443",
			want:       "203.0.113.5",
		},
		{
			name:       "ipv6 with port splits correctly",
			remoteAddr: "[2001:db8::1]:443",
			want:       "2001:db8::1",
		},
		{
			// CF headers must NOT influence the security IP — it is the
			// PROXY-decoded RemoteAddr, never XFF/CF.
			name:       "CF headers present, still RemoteAddr",
			remoteAddr: "203.0.113.5:443",
			headers:    []string{"CF-Connecting-IP", "198.51.100.7", "CF-Ray", "abc"},
			want:       "203.0.113.5",
		},
		{
			// XFF must NOT influence the security IP.
			name:       "XFF present, still RemoteAddr",
			remoteAddr: "203.0.113.5:443",
			headers:    []string{"X-Forwarded-For", "198.51.100.1, 70.0.0.2, 198.51.100.9"},
			want:       "203.0.113.5",
		},
		{
			name:       "no port falls back to RemoteAddr as-is",
			remoteAddr: "203.0.113.5",
			want:       "203.0.113.5",
		},
		{
			name:       "ipv6 no port falls back",
			remoteAddr: "2001:db8::1",
			want:       "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newReq(tt.remoteAddr, tt.headers...)
			if got := securityClientIP(r); got != tt.want {
				t.Errorf("securityClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestForwardedIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    []string
		want       string
	}{
		{
			name:       "no headers returns ::",
			remoteAddr: "203.0.113.5:443",
			want:       "::",
		},
		{
			name:       "CF-Connecting-IP wins",
			remoteAddr: "203.0.113.5:443",
			headers:    []string{"CF-Connecting-IP", "198.51.100.7", "CF-Ray", "abc"},
			want:       "198.51.100.7",
		},
		{
			// Rightmost XFF entry = closest trusted hop.
			name:       "rightmost XFF when no CF",
			remoteAddr: "203.0.113.5:443",
			headers:    []string{"X-Forwarded-For", "198.51.100.1, 70.0.0.2, 198.51.100.9"},
			want:       "198.51.100.9",
		},
		{
			// X-Real-IP does NOT feed forwardedIP per the spec — only
			// CF-Connecting-IP and XFF do. Deliberate per spec.
			name:       "X-Real-IP only does not feed forwardedIP",
			remoteAddr: "203.0.113.5:443",
			headers:    []string{"X-Real-IP", "198.51.100.3"},
			want:       "::",
		},
		{
			// Junk CF value falls through to XFF/::; here no XFF, so ::.
			name:       "garbage CF-Connecting-IP falls through to ::",
			remoteAddr: "203.0.113.5:443",
			headers:    []string{"CF-Connecting-IP", "notanip", "CF-Ray", "abc"},
			want:       "::",
		},
		{
			// Junk CF value falls through to the rightmost XFF entry.
			name:       "garbage CF-Connecting-IP falls through to XFF",
			remoteAddr: "203.0.113.5:443",
			headers:    []string{"CF-Connecting-IP", "notanip", "X-Forwarded-For", "70.0.0.2, 198.51.100.9"},
			want:       "198.51.100.9",
		},
		{
			name:       "single-entry XFF",
			remoteAddr: "203.0.113.5:443",
			headers:    []string{"X-Forwarded-For", "198.51.100.9"},
			want:       "198.51.100.9",
		},
		{
			name:       "garbage rightmost XFF returns ::",
			remoteAddr: "203.0.113.5:443",
			headers:    []string{"X-Forwarded-For", "198.51.100.1, notanip"},
			want:       "::",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newReq(tt.remoteAddr, tt.headers...)
			if got := forwardedIP(r); got != tt.want {
				t.Errorf("forwardedIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFrontProxy(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    string
	}{
		{
			name: "no headers returns empty",
			want: "",
		},
		{
			name:    "CF-Connecting-IP present",
			headers: []string{"CF-Connecting-IP", "198.51.100.7"},
			want:    "cloudflare",
		},
		{
			name:    "CF-Ray present",
			headers: []string{"CF-Ray", "abc"},
			want:    "cloudflare",
		},
		{
			// Presence-based: junk CF value still labels cloudflare.
			name:    "garbage CF-Connecting-IP still cloudflare",
			headers: []string{"CF-Connecting-IP", "notanip"},
			want:    "cloudflare",
		},
		{
			name:    "X-Forwarded-For present",
			headers: []string{"X-Forwarded-For", "198.51.100.9"},
			want:    "forwarded",
		},
		{
			name:    "X-Real-IP present",
			headers: []string{"X-Real-IP", "198.51.100.3"},
			want:    "forwarded",
		},
		{
			// CF takes precedence over forwarded headers.
			name:    "CF beats XFF",
			headers: []string{"CF-Ray", "abc", "X-Forwarded-For", "198.51.100.9"},
			want:    "cloudflare",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newReq("203.0.113.5:443", tt.headers...)
			if got := frontProxy(r); got != tt.want {
				t.Errorf("frontProxy() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCapPath_QueryStripReleasesParentBacking(t *testing.T) {
	// A short path in front of a huge stripped query must not keep the
	// parent string's backing array alive once buffered.
	parent := "/api/users?" + strings.Repeat("q", 1<<20)
	got := capPath(parent)
	if got != "/api/users" {
		t.Fatalf("got %q, want %q", got, "/api/users")
	}
	if unsafe.StringData(got) == unsafe.StringData(parent) {
		t.Errorf("stripped path shares the parent's backing array; want a clone")
	}
	// Unstripped short path: must STILL be an owned copy. Even a short
	// query-less path can be a slice of a huge request line (absolute-form
	// URI with a long host, junk long method) — capPath can't see the
	// backing, so it must always clone before the row is buffered.
	p := "/health" + strings.Repeat("x", 1<<20)
	short := p[:7]
	got2 := capPath(short)
	if got2 != "/health" {
		t.Fatalf("got %q, want %q", got2, "/health")
	}
	if unsafe.StringData(got2) == unsafe.StringData(p) {
		t.Errorf("unstripped short path shares the caller's backing array; want an owned copy")
	}
}
