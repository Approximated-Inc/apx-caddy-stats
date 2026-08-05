package apxstats

import (
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestHttpVersionOrUnknown(t *testing.T) {
	cases := []struct {
		name  string
		major int
		minor int
		want  string
	}{
		{"http2", 2, 0, "2"},
		{"http3", 3, 0, "3"},
		{"http11", 1, 1, "1.1"},
		{"http10", 1, 0, "other"},
		{"http09", 0, 9, "other"},
		{"zero", 0, 0, "other"},
		{"future4", 4, 0, "other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{ProtoMajor: tc.major, ProtoMinor: tc.minor}
			if got := httpVersionOrUnknown(r); got != tc.want {
				t.Errorf("httpVersionOrUnknown(%d.%d) = %q, want %q", tc.major, tc.minor, got, tc.want)
			}
		})
	}
}

func TestPathBucket(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// No replacement: plain segments. Note v1 is kept (len 2, has a
		// digit but len<8, no '.'/'-' adjacency, not all-digits).
		{"plain", "/api/v1/users", "/api/v1/users"},
		// All-digits segment.
		{"all_digits", "/api/v1/123", "/api/v1/*"},
		// UUID segment (already lowercase).
		{"uuid", "/u/550e8400-e29b-41d4-a716-446655440000", "/u/*"},
		// Digit adjacent to both '-' and '.'.
		{"report_pdf", "/files/report-2024.pdf", "/files/*"},
		// Digit adjacent to '.'.
		{"v1_2", "/v1.2/x", "/*/x"},
		// len>=8 + has letter + >=3 digits (slug-id).
		{"slug_id", "/products/abc123def456ghi", "/products/*"},
		// Segment longer than 64 chars -> starred.
		{"over64", "/a/" + strings.Repeat("z", 65) + "/b", "/a/*/b"},
		// Only first 3 non-empty segments are kept.
		{"first3", "/a/b/c/d/e", "/a/b/c"},
		// Empty segments from leading/double slashes are ignored.
		{"empty_segments", "//api///v1", "/api/v1"},
		// Whole path lowercased.
		{"lowercase", "/Api/V1/Users", "/api/v1/users"},
		// Query and fragment stripped.
		{"query_frag", "/search?q=secret#frag", "/search"},
		// Empty inputs -> "/".
		{"empty", "", "/"},
		{"root", "/", "/"},
		// v1 must NOT be over-starred: len 2, single digit, no '.'/'-'
		// adjacency, fails slug rule (len<8) -> kept verbatim.
		{"v1_not_starred", "/v1/x", "/v1/x"},
		// Borderline: a digit at a segment boundary is not adjacent to
		// any '.'/'-' within the segment, so "users" stays and "2"
		// (all-digits) stars. Confirms adjacency is intra-segment only.
		{"boundary_digit", "/users/2", "/users/*"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathBucket(tc.in); got != tc.want {
				t.Errorf("pathBucket(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestPathBucketTruncation(t *testing.T) {
	// Three 50-char non-dynamic (letters-only) segments: the joined
	// result "/<50>/<50>/<50>" is 153 bytes, must truncate to <=128
	// and stay valid UTF-8.
	seg := strings.Repeat("a", 50)
	in := "/" + seg + "/" + seg + "/" + seg
	got := pathBucket(in)
	if len(got) > L7PathBucketMaxBytes {
		t.Errorf("len(pathBucket(...)) = %d, want <= %d", len(got), L7PathBucketMaxBytes)
	}
	if !utf8.ValidString(got) {
		t.Errorf("pathBucket(...) = %q is not valid UTF-8", got)
	}
}

func TestPathBucketTruncationMultibyte(t *testing.T) {
	// A multibyte (3-byte 'あ') segment straddling the 128-byte boundary:
	// the UTF-8-safe truncate must not split a code point.
	seg := strings.Repeat("あ", 50) // 150 bytes, letters-only (kept verbatim)
	in := "/" + seg
	got := pathBucket(in)
	if len(got) > L7PathBucketMaxBytes {
		t.Errorf("len(pathBucket(...)) = %d, want <= %d", len(got), L7PathBucketMaxBytes)
	}
	if !utf8.ValidString(got) {
		t.Errorf("pathBucket(...) = %q is not valid UTF-8", got)
	}
}

func TestStatusBucket(t *testing.T) {
	cases := []struct {
		code uint16
		want uint8
	}{
		{100, 1},
		{200, 2},
		{301, 3},
		{404, 4},
		{500, 5},
		{599, 5},
		{0, 0},
		{99, 0},
		{600, 0},
		{999, 0},
	}
	for _, tc := range cases {
		if got := statusBucket(tc.code); got != tc.want {
			t.Errorf("statusBucket(%d) = %d, want %d", tc.code, got, tc.want)
		}
	}
}
