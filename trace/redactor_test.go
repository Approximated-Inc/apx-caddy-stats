package apxtrace

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedactHeaders_SensitiveAreHashed(t *testing.T) {
	r := DefaultRedactor()
	h := http.Header{}
	h.Set("Authorization", "Bearer abc123")
	h.Set("Cookie", "session=xyz")
	h.Set("Content-Type", "application/json")

	out := r.RedactHeaders(h)
	require.True(t, len(out["Authorization"][0]) > 0)
	require.Contains(t, out["Authorization"][0], "<sha256:")
	require.Contains(t, out["Cookie"][0], "<sha256:")
	require.Equal(t, "application/json", out["Content-Type"][0])
}

func TestRedactHeaders_CaseInsensitive(t *testing.T) {
	r := DefaultRedactor()
	h := http.Header{}
	h.Set("authorization", "Bearer xyz")
	out := r.RedactHeaders(h)
	require.Contains(t, out["Authorization"][0], "<sha256:")
}

func TestRedactHeaders_StableHashForSameValue(t *testing.T) {
	r := DefaultRedactor()
	h1 := http.Header{}
	h1.Set("Cookie", "session=xyz")
	h2 := http.Header{}
	h2.Set("Cookie", "session=xyz")

	r1 := r.RedactHeaders(h1)
	r2 := r.RedactHeaders(h2)
	require.Equal(t, r1["Cookie"][0], r2["Cookie"][0])
}

func TestRedactHeaders_OutputFormatIsStable(t *testing.T) {
	r := DefaultRedactor()
	h := http.Header{}
	h.Set("Authorization", "Bearer abc123")
	out := r.RedactHeaders(h)

	// Locks the cross-language contract: Elixir produces the same string
	// from :crypto.hash(:sha256, v) |> binary_part(0, 6) |> Base.encode16(case: :lower)
	require.Equal(t, "<sha256:c84d069b7e1e>", out["Authorization"][0])
	require.Regexp(t, `^<sha256:[0-9a-f]{12}>$`, out["Authorization"][0])
}
