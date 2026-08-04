package apxstats

import (
	"net/http"
	"strings"
)

// L7PathBucketMaxBytes caps the bucketed path label, shared with the
// Phoenix side so both ends agree on the boundary. UTF-8-boundary-safe.
const L7PathBucketMaxBytes = 128

// pathBucket reduces a raw request path to a low-cardinality label: it
// keeps the first <=3 non-empty path segments (query/fragment stripped,
// lowercased) and replaces any segment that looks like an identifier
// (all-digits, UUID, slug-id, digit-adjacent-to-'.'/'-', or >64 chars)
// with "*". The result is "/"-joined with a leading slash and truncated
// UTF-8-safely to L7PathBucketMaxBytes.
func pathBucket(rawPath string) string {
	// 1. Strip query and fragment (whichever comes first).
	if i := strings.IndexByte(rawPath, '?'); i >= 0 {
		rawPath = rawPath[:i]
	}
	if i := strings.IndexByte(rawPath, '#'); i >= 0 {
		rawPath = rawPath[:i]
	}

	// 2. Lowercase the whole path.
	rawPath = strings.ToLower(rawPath)

	// 3. Take the first <=3 non-empty segments.
	kept := make([]string, 0, 3)
	for _, seg := range strings.Split(rawPath, "/") {
		if seg == "" {
			continue
		}
		// 4. Star dynamic-looking segments.
		if isDynamicSegment(seg) {
			seg = "*"
		}
		kept = append(kept, seg)
		if len(kept) == 3 {
			break
		}
	}

	// 5. Re-join with a leading slash; empty path -> "/".
	result := "/" + strings.Join(kept, "/")

	// 6. UTF-8-safe truncate, reusing the coraza helper.
	return truncateBytes(result, L7PathBucketMaxBytes)
}

// isDynamicSegment reports whether a lowercased path segment looks like a
// per-request identifier that should collapse to "*".
func isDynamicSegment(seg string) bool {
	if len(seg) > 64 {
		return true
	}
	if isAllDigits(seg) {
		return true
	}
	if isUUID(seg) {
		return true
	}
	if isSlugID(seg) {
		return true
	}
	if hasDigitAdjacentToDotOrDash(seg) {
		return true
	}
	return false
}

// isAllDigits: ^[0-9]+$.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isUUID: ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$
// (input is already lowercased).
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHexLower(s[i]) {
				return false
			}
		}
	}
	return true
}

// isSlugID: len >= 8 AND has >=1 letter AND has >=3 digits (e.g.
// "abc123def456").
func isSlugID(s string) bool {
	if len(s) < 8 {
		return false
	}
	letters, digits := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			letters++
		}
	}
	return letters >= 1 && digits >= 3
}

// hasDigitAdjacentToDotOrDash reports whether any digit sits immediately
// before or after a '.' or '-' within the segment (e.g. "report-2024",
// "v1.2", "2024.pdf").
func hasDigitAdjacentToDotOrDash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '.' && s[i] != '-' {
			continue
		}
		if i > 0 && isDigit(s[i-1]) {
			return true
		}
		if i+1 < len(s) && isDigit(s[i+1]) {
			return true
		}
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexLower(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// httpVersionOrUnknown maps a request's negotiated HTTP version to the
// low-cardinality label set the l7_httpversion track records. The Phoenix
// `normalize_l7_httpversion_row/1` whitelist is `1.1 | 2 | 3 | other`, so
// anything outside those (HTTP/1.0, HTTP/0.9, future majors) collapses to
// "other" rather than producing a row Phoenix would reject.
func httpVersionOrUnknown(r *http.Request) string {
	switch {
	case r.ProtoMajor == 2:
		return "2"
	case r.ProtoMajor == 3:
		return "3"
	case r.ProtoMajor == 1 && r.ProtoMinor == 1:
		return "1.1"
	default:
		return "other"
	}
}

// statusBucket reduces an HTTP status code to its leading digit (1xx..5xx)
// as a uint8 1..5, or 0 for anything outside the 100..599 range (0, 99,
// 600+). Matches the status_bucket dimension in the l7_httpversion row.
func statusBucket(code uint16) uint8 {
	d := code / 100
	if d >= 1 && d <= 5 {
		return uint8(d)
	}
	return 0
}
