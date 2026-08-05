package apxstats

import "net/http"

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
