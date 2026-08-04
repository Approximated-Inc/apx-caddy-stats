package apxtrace

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSnapshot_CapturesMethodURIHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "https://example.com/foo?x=1", nil)
	r.Header.Set("X-Foo", "bar")
	s := Snapshot(r)
	require.Equal(t, "GET", s.Method)
	require.Equal(t, "/foo?x=1", s.URI)
	require.Equal(t, "bar", s.Headers.Get("X-Foo"))
}

func findHeaderChange(t *testing.T, entries []HeaderChange, name string) HeaderChange {
	t.Helper()
	for _, e := range entries {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("expected header change for %q; got %+v", name, entries)
	return HeaderChange{}
}

func TestDiffSnapshots_DetectsHeaderAddRemoveChange(t *testing.T) {
	before := RequestSnapshot{
		Method:  "GET",
		URI:     "/a",
		Headers: http.Header{"X-Keep": {"1"}, "X-Remove": {"x"}, "X-Change": {"old"}},
	}
	after := RequestSnapshot{
		Method:  "GET",
		URI:     "/a",
		Headers: http.Header{"X-Keep": {"1"}, "X-Add": {"y"}, "X-Change": {"new"}},
	}
	diff := DiffSnapshots(before, after)

	added := findHeaderChange(t, diff.HeadersAdded, "X-Add")
	require.Equal(t, []string{"y"}, added.After)
	require.Empty(t, added.Before)

	removed := findHeaderChange(t, diff.HeadersRemoved, "X-Remove")
	require.Equal(t, []string{"x"}, removed.Before)
	require.Empty(t, removed.After)

	changed := findHeaderChange(t, diff.HeadersChanged, "X-Change")
	require.Equal(t, []string{"old"}, changed.Before)
	require.Equal(t, []string{"new"}, changed.After)

	for _, e := range diff.HeadersChanged {
		require.NotEqual(t, "X-Keep", e.Name, "unchanged header should not be in HeadersChanged")
	}
	require.Empty(t, diff.URIChange)
}

func TestDiffSnapshots_URIAndMethodChange(t *testing.T) {
	before := RequestSnapshot{Method: "GET", URI: "/a", Headers: http.Header{}}
	after := RequestSnapshot{Method: "POST", URI: "/b", Headers: http.Header{}}
	diff := DiffSnapshots(before, after)
	require.Equal(t, "/a", diff.URIChange.Before)
	require.Equal(t, "/b", diff.URIChange.After)
	require.Equal(t, "GET", diff.MethodChange.Before)
	require.Equal(t, "POST", diff.MethodChange.After)
}

func TestDiffSnapshots_DetectsMultiValueHeaderChange(t *testing.T) {
	before := RequestSnapshot{
		Method:  "GET",
		URI:     "/a",
		Headers: http.Header{"Set-Cookie": {"a=1", "b=2"}},
	}
	after := RequestSnapshot{
		Method:  "GET",
		URI:     "/a",
		Headers: http.Header{"Set-Cookie": {"a=1"}},
	}
	diff := DiffSnapshots(before, after)

	changed := findHeaderChange(t, diff.HeadersChanged, "Set-Cookie")
	// Set-Cookie is sensitive → both before and after values should be redacted.
	require.Len(t, changed.Before, 2)
	require.Len(t, changed.After, 1)
	for _, v := range changed.Before {
		require.True(t, strings.HasPrefix(v, "<sha256:"), "expected redacted Set-Cookie value, got %q", v)
	}
	for _, v := range changed.After {
		require.True(t, strings.HasPrefix(v, "<sha256:"), "expected redacted Set-Cookie value, got %q", v)
	}
}

func TestDiffSnapshots_OrderingIsSorted(t *testing.T) {
	before := RequestSnapshot{Headers: http.Header{}}
	after := RequestSnapshot{
		Headers: http.Header{"Z-Last": {"1"}, "A-First": {"1"}, "M-Mid": {"1"}},
	}
	diff := DiffSnapshots(before, after)
	names := make([]string, len(diff.HeadersAdded))
	for i, e := range diff.HeadersAdded {
		names[i] = e.Name
	}
	require.Equal(t, []string{"A-First", "M-Mid", "Z-Last"}, names)
}

func TestDiffSnapshots_RedactsSensitiveHeaderValues(t *testing.T) {
	before := RequestSnapshot{
		Method:  "GET",
		URI:     "/a",
		Headers: http.Header{},
	}
	after := RequestSnapshot{
		Method:  "GET",
		URI:     "/a",
		Headers: http.Header{"Authorization": {"Bearer super-secret-token"}},
	}
	diff := DiffSnapshots(before, after)

	added := findHeaderChange(t, diff.HeadersAdded, "Authorization")
	require.Len(t, added.After, 1)
	require.True(t, strings.HasPrefix(added.After[0], "<sha256:"),
		"expected Authorization value to be redacted, got %q", added.After[0])
	require.NotContains(t, added.After[0], "super-secret-token")
}

func TestDiffSnapshots_NonSensitiveHeaderValuesNotRedacted(t *testing.T) {
	before := RequestSnapshot{Headers: http.Header{}}
	after := RequestSnapshot{Headers: http.Header{"X-Custom": {"plain-value"}}}
	diff := DiffSnapshots(before, after)

	added := findHeaderChange(t, diff.HeadersAdded, "X-Custom")
	require.Equal(t, []string{"plain-value"}, added.After)
}

func TestSnapshotDiff_Empty(t *testing.T) {
	require.True(t, SnapshotDiff{}.Empty())
	require.False(t, SnapshotDiff{
		HeadersAdded: []HeaderChange{{Name: "X-Foo"}},
	}.Empty())
	require.False(t, SnapshotDiff{
		HeadersRemoved: []HeaderChange{{Name: "X-Foo"}},
	}.Empty())
	require.False(t, SnapshotDiff{
		HeadersChanged: []HeaderChange{{Name: "X-Foo"}},
	}.Empty())
	require.False(t, SnapshotDiff{URIChange: &Change{}}.Empty())
	require.False(t, SnapshotDiff{MethodChange: &Change{}}.Empty())
}

func TestDiffHeadersOnly_DetectsHeaderAddRemoveChange(t *testing.T) {
	before := http.Header{"X-Keep": {"1"}, "X-Remove": {"x"}, "X-Change": {"old"}}
	after := http.Header{"X-Keep": {"1"}, "X-Add": {"y"}, "X-Change": {"new"}}
	diff := DiffHeadersOnly(before, after, DefaultRedactor())

	added := findHeaderChange(t, diff.HeadersAdded, "X-Add")
	require.Equal(t, []string{"y"}, added.After)
	require.Empty(t, added.Before)

	removed := findHeaderChange(t, diff.HeadersRemoved, "X-Remove")
	require.Equal(t, []string{"x"}, removed.Before)
	require.Empty(t, removed.After)

	changed := findHeaderChange(t, diff.HeadersChanged, "X-Change")
	require.Equal(t, []string{"old"}, changed.Before)
	require.Equal(t, []string{"new"}, changed.After)

	// URI/method are never populated in a headers-only diff.
	require.Nil(t, diff.URIChange)
	require.Nil(t, diff.MethodChange)
}

func TestDiffHeadersOnly_EmptyWhenIdentical(t *testing.T) {
	h := http.Header{"Content-Type": {"text/plain"}, "X-Foo": {"bar"}}
	diff := DiffHeadersOnly(h, h, DefaultRedactor())
	require.True(t, diff.Empty(), "expected empty diff for identical headers")
}

func TestDiffHeadersOnly_OrderingIsSorted(t *testing.T) {
	before := http.Header{}
	after := http.Header{"Z-Last": {"1"}, "A-First": {"1"}, "M-Mid": {"1"}}
	diff := DiffHeadersOnly(before, after, DefaultRedactor())
	names := make([]string, len(diff.HeadersAdded))
	for i, e := range diff.HeadersAdded {
		names[i] = e.Name
	}
	require.Equal(t, []string{"A-First", "M-Mid", "Z-Last"}, names)
}

func TestDiffHeadersOnly_RedactsSensitiveValues(t *testing.T) {
	before := http.Header{"Set-Cookie": {"session=plaintext"}}
	after := http.Header{"Set-Cookie": {"session=newplaintext"}}
	diff := DiffHeadersOnly(before, after, DefaultRedactor())

	changed := findHeaderChange(t, diff.HeadersChanged, "Set-Cookie")
	require.Len(t, changed.Before, 1)
	require.Len(t, changed.After, 1)
	require.True(t, strings.HasPrefix(changed.Before[0], "<sha256:"),
		"expected Set-Cookie before value redacted, got %q", changed.Before[0])
	require.True(t, strings.HasPrefix(changed.After[0], "<sha256:"),
		"expected Set-Cookie after value redacted, got %q", changed.After[0])
}

func TestDiffHeadersOnly_NilRedactorUsesDefault(t *testing.T) {
	before := http.Header{}
	after := http.Header{"Authorization": {"Bearer secret"}}
	diff := DiffHeadersOnly(before, after, nil)
	added := findHeaderChange(t, diff.HeadersAdded, "Authorization")
	require.Len(t, added.After, 1)
	require.True(t, strings.HasPrefix(added.After[0], "<sha256:"))
}
