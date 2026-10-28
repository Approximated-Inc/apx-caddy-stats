package apxstats

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// rawRequest parses a request line the way the server does, so RequestURI
// keeps the raw target.
func rawRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	require.NoError(t, err)
	return r
}

func get(t *testing.T, target string, headers ...string) *http.Request {
	t.Helper()
	raw := "GET " + target + " HTTP/1.1\r\nHost: x\r\n"
	for _, h := range headers {
		raw += h + "\r\n"
	}
	return rawRequest(t, raw+"\r\n")
}

func TestStaticAssetPath(t *testing.T) {
	cases := map[string]bool{
		"/app.js": true, "/a/b/STYLE.CSS": true, "/f.woff2?v=3": true, "/x.wasm": true,
		"/index.html": false, "/api/v1/users": false, "/a.php": false, "/js": false, "/a.": false,
		"/dir.js/file": false, "/.js": true,
	}
	for target, want := range cases {
		require.Equal(t, want, staticAssetPath(get(t, target)), target)
	}
	require.True(t, staticAssetPath(rawRequest(t, "HEAD /a.png HTTP/1.1\r\nHost: x\r\n\r\n")))
	require.False(t, staticAssetPath(rawRequest(t, "POST /a.png HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")))
}

// B8: the block-mode skip screen.
func TestWAFSkippableStatic(t *testing.T) {
	yes := []*http.Request{
		get(t, "/a.js"),
		get(t, "/a.js?v=3"),
		get(t, "/static/app-1.2_x~y.min.css?v=1&b=2"),
		get(t, "/a.js", "User-Agent: Mozilla/5.0 (X11) Firefox/120", "Cookie: s=abc; t=1"),
	}
	for _, r := range yes {
		require.True(t, wafSkippableStatic(r), r.RequestURI)
	}
	no := map[string]*http.Request{
		"escaped query":      get(t, "/a.js?id=1%27"),
		"plus in query":      get(t, "/a.js?q=a+b"),
		"quote in query":     get(t, "/a.js?q='1"),
		"slash in query":     get(t, "/a.js?q=/etc"),
		"long query":         get(t, "/a.js?"+strings.Repeat("a", 65)),
		"traversal":          get(t, "/../a.js"),
		"dot dot":            get(t, "/a/..js/b.js"),
		"double slash":       get(t, "//a.js"),
		"escaped path":       get(t, "/a%2e.js"),
		"jndi user agent":    get(t, "/a.js", "User-Agent: ${jndi:ldap://x/a}"),
		"html in header":     get(t, "/a.js", "Referer: <script>"),
		"php":                get(t, "/a.php"),
		"absolute form":      get(t, "http://x/a.js?q=%27"),
		"post":               rawRequest(t, "POST /a.js HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi"),
		"get with body":      rawRequest(t, "GET /a.js HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi"),
		"chunked":            rawRequest(t, "GET /a.js HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
		"long path":          get(t, "/"+strings.Repeat("a", 254)+".js"),
		"space-free unicode": get(t, "/\xc3\xa9.js"),
	}
	for name, r := range no {
		require.False(t, wafSkippableStatic(r), name)
	}
	require.True(t, wafSkippableStatic(get(t, "/"+strings.Repeat("a", 252)+".js")), "256 chars after the slash")
}

// The hot-path checks don't allocate.
func TestStaticAssetChecksDoNotAllocate(t *testing.T) {
	r := get(t, "/static/app.min.JS?v=12", "User-Agent: Mozilla/5.0")
	allocs := testing.AllocsPerRun(100, func() {
		_ = staticAssetPath(r)
		_ = wafSkippableStatic(r)
	})
	require.Zero(t, allocs)
}
