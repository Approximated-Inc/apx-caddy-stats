package apxstats

import (
	"net/http"
	"testing"
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
