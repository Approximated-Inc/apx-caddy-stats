package apxstats

import (
	"net/http"
	"strings"
)

// One definition of "static asset" for the WAF skip and admission classes.

var staticAssetExts = [...]string{
	"css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "bmp",
	"woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "ogg", "wav", "m4a", "wasm",
}

// staticExt reports whether path's final segment has a static extension.
// ASCII case-insensitive, no allocation.
func staticExt(path string) bool {
	seg := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		seg = path[i+1:]
	}
	dot := strings.LastIndexByte(seg, '.')
	if dot < 0 || dot == len(seg)-1 {
		return false
	}
	ext := seg[dot+1:]
	if len(ext) > 5 {
		return false
	}
	for _, e := range staticAssetExts {
		if len(e) == len(ext) && strings.EqualFold(e, ext) {
			return true
		}
	}
	return false
}

// staticAssetPath is admission class P3: a GET or HEAD for a path with a
// static extension. The query string is ignored (cache busting).
func staticAssetPath(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return staticExt(r.URL.Path)
}

// wafSkippableStatic is stricter than staticAssetPath, because block mode
// must not become a bypass: no body, a plain path and query (no escapes,
// traversal, quotes or spaces) and no header value carrying an injection
// marker. Anything else is evaluated as usual.
func wafSkippableStatic(r *http.Request) bool {
	if !staticAssetPath(r) {
		return false
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 || r.Header.Get("Transfer-Encoding") != "" {
		return false
	}
	path, query := r.URL.EscapedPath(), r.URL.RawQuery
	if r.RequestURI != "" && r.RequestURI != "*" {
		// The raw target, so encoded bytes can't hide behind a decoded Path.
		path, query = r.RequestURI, ""
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path, query = path[:i], path[i+1:]
		}
	}
	if !plainStaticPath(path) || !plainStaticQuery(query) || r.URL.Fragment != "" {
		return false
	}
	for _, vs := range r.Header {
		for _, v := range vs {
			if headerHasInjectionMarker(v) {
				return false
			}
		}
	}
	return true
}

// plainStaticPath matches ^/[A-Za-z0-9_.~/-]{1,256}$ with no ".." or "//".
func plainStaticPath(p string) bool {
	if len(p) < 2 || len(p) > 257 || p[0] != '/' {
		return false
	}
	for i := 1; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '.', c == '~', c == '-':
		case c == '/':
			if p[i-1] == '/' {
				return false
			}
		default:
			return false
		}
	}
	return !strings.Contains(p, "..")
}

// plainStaticQuery matches "" or ^[A-Za-z0-9_.=&-]{1,64}$.
func plainStaticQuery(q string) bool {
	if q == "" {
		return true
	}
	if len(q) > 64 {
		return false
	}
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '.', c == '=', c == '&', c == '-':
		default:
			return false
		}
	}
	return true
}

func headerHasInjectionMarker(v string) bool {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '<', 0, '\r', '\n':
			return true
		case '$':
			if i+1 < len(v) && v[i+1] == '{' {
				return true
			}
		}
	}
	return false
}
