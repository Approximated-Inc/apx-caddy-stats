package apxstats

import (
	"net"
	"net/http"
)

// securityClientIP returns the PROXY-decoded real client IP from
// r.RemoteAddr (the connection's remote address, which Caddy's
// PROXY-protocol listener rewrites to the real client). Host only
// (port stripped). This is the authoritative security IP (matches the
// L4 recorder + coraza), NOT XFF — never trust forwarded headers here.
func securityClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// No port (or unparseable) — use RemoteAddr as-is.
		host = r.RemoteAddr
	}
	// Canonicalize to a clean IP string Phoenix normalize_ip/1 accepts.
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return trimSpace(host)
}

// forwardedIP returns the CLAIMED end-user IP for CDN-fronted vhosts:
// CF-Connecting-IP if present+parseable, else the rightmost
// X-Forwarded-For entry if parseable, else "::". Informational only
// (spoofable for the generic XFF path).
func forwardedIP(r *http.Request) string {
	if cf := trimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		if ip := net.ParseIP(cf); ip != nil {
			return ip.String()
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Rightmost entry = the IP added by the closest trusted hop.
		var last string
		if i := lastIndexByte(xff, ','); i >= 0 {
			last = trimSpace(xff[i+1:])
		} else {
			last = trimSpace(xff)
		}
		if ip := net.ParseIP(last); ip != nil {
			return ip.String()
		}
	}
	return "::"
}

// frontProxy classifies the fronting proxy by header PRESENCE only
// (no value parsing): "cloudflare" if CF-Connecting-IP or CF-Ray
// present; "forwarded" if X-Forwarded-For or X-Real-IP present; else
// "". Analytics label only.
func frontProxy(r *http.Request) string {
	if r.Header.Get("CF-Connecting-IP") != "" || r.Header.Get("CF-Ray") != "" {
		return "cloudflare"
	}
	if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-IP") != "" {
		return "forwarded"
	}
	return ""
}
