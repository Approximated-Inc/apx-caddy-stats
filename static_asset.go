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
	// Only the final segment may hold a dot: /index.php/x.css is PATH_INFO
	// into a script, not a file. Costs the skip on dotted directories
	// (/v1.2/app.js), which are then evaluated as usual.
	if i := strings.LastIndexByte(path, '/'); strings.IndexByte(path[:i], '.') >= 0 {
		return false
	}
	for name, vs := range r.Header {
		for _, v := range vs {
			if !staticSkipHeaderSafe(name, v) {
				return false
			}
		}
	}
	return true
}

// staticSkipHeaderSafe screens one header value for the block-mode skip.
// CRS reads cookies, User-Agent and Referer for SQLi/XSS/RCE, so those get
// a strict character set and an SQL keyword check; every header gets the
// shellshock, log4shell, markup and line-break checks. Over-strict is fine:
// a rejected request is evaluated as usual.
func staticSkipHeaderSafe(name, v string) bool {
	if headerHasInjectionMarker(v) {
		return false
	}
	switch name {
	case "Cookie":
		return cookieHeaderSafe(v) && !hasSQLKeyword(v)
	case "User-Agent":
		return textHeaderSafe(v, true) && !hasSQLKeyword(v)
	case "Referer":
		return textHeaderSafe(v, false) && !hasSQLKeyword(v)
	}
	return true
}

// cookieHeaderSafe: name=value pairs joined by "; ", each byte in
// [A-Za-z0-9_.~=:/+-]. No quotes, spaces, '%' (CRS url-decodes cookies),
// comment markers or parentheses.
func cookieHeaderSafe(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '.', c == '~', c == '=', c == ':', c == '/', c == '+':
		case c == '-':
			if i+1 < len(v) && v[i+1] == '-' {
				return false
			}
		case c == ';':
			if i+1 >= len(v) || v[i+1] != ' ' {
				return false
			}
			i++
		default:
			return false
		}
	}
	return true
}

// textHeaderSafe allows letters, digits and _ . ~ = : / + - , ( ) ; ? & !
// plus spaces when spaces is set. No quotes, backticks, backslashes, '%',
// '*', '|', '#', '--' or path markers like /bin/ and /etc/.
func textHeaderSafe(v string, spaces bool) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '.', c == '~', c == '=', c == ':', c == '+', c == ',',
			c == '(', c == ')', c == ';', c == '?', c == '&', c == '!':
		case c == ' ':
			if !spaces {
				return false
			}
		case c == '-':
			if i+1 < len(v) && v[i+1] == '-' {
				return false
			}
		case c == '/':
			if hasPrefixFold(v[i:], "/bin/") || hasPrefixFold(v[i:], "/etc/") {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// sqlKeywords are words with no business in a browser's static-asset
// request headers. Matched as whole words, ASCII case-insensitive.
var sqlKeywords = [...]string{
	"select", "union", "insert", "update", "delete", "drop", "truncate", "alter",
	"sleep", "pg_sleep", "benchmark", "waitfor", "exec", "execute", "declare",
	"having", "information_schema", "load_file", "outfile", "dumpfile", "xp_cmdshell",
}

func hasSQLKeyword(v string) bool {
	start := -1
	for i := 0; i <= len(v); i++ {
		word := i < len(v) && (v[i] >= 'a' && v[i] <= 'z' || v[i] >= 'A' && v[i] <= 'Z' || v[i] == '_')
		switch {
		case word && start < 0:
			start = i
		case !word && start >= 0:
			w := v[start:i]
			for _, k := range sqlKeywords {
				if len(k) == len(w) && strings.EqualFold(k, w) {
					return true
				}
			}
			start = -1
		}
	}
	return false
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
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

// headerHasInjectionMarker: markup, NUL/CR/LF, backticks, ${ (log4shell,
// shell expansion) and "()" followed by "{" (shellshock), in any header.
func headerHasInjectionMarker(v string) bool {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '<', 0, '\r', '\n', '`':
			return true
		case '$':
			if i+1 < len(v) && v[i+1] == '{' {
				return true
			}
		case '(':
			if i+1 < len(v) && v[i+1] == ')' {
				j := i + 2
				for j < len(v) && (v[j] == ' ' || v[j] == '\t') {
					j++
				}
				if j < len(v) && v[j] == '{' {
					return true
				}
			}
		}
	}
	return false
}
