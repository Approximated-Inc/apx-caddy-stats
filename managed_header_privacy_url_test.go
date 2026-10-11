package apxstats

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// hidden keeps the managed value's fragment out of failure messages.
func hidden(s string) string { return strings.ReplaceAll(s, "7f3a9c", "…") }

// A managed value holding a literal '+' is masked where CRS (urlDecodeUni,
// form decoding) has turned the '+' into a space.
func TestManagedHeaderPrivacyPlusValueInURL(t *testing.T) {
	pairs := []managedHeaderCredential{{Name: "X-Partner-Key", Value: "abc+def/7f3a9c=="}}
	policy := compileManagedHeaderPolicy(pairs)
	for _, uri := range []string{"/keys/abc+def%2F7f3a9c==/rotate", "/keys/abc+def%252F7f3a9c==/rotate"} {
		for _, carried := range []bool{false, true} {
			got := policy.redactURI(uri, carried)
			require.True(t, got == "/keys/[masked]/rotate", "redactURI(%q, %v) = %q", hidden(uri), carried, hidden(got))
			o := privacyRunOptions{pairs: pairs, rules: `SecRule REQUEST_HEADERS:Accept "@rx ." "id:900141,phase:1,pass,log"`, target: uri}
			if carried {
				o.prepare = setHeader("X-Partner-Key", "abc+def/7f3a9c==")
			}
			run := runPrivacyPipeline(t, o)
			require.Len(t, run.detections, 1)
			require.Len(t, run.events, 1)
			require.False(t, leaksValueFragment(run.detections[0].RequestURI), "request_uri shipped the value: %q", hidden(run.detections[0].RequestURI))
			require.False(t, leaksValueFragment(run.events[0].Path), "request_events.path shipped the value: %q", hidden(run.events[0].Path))
			require.False(t, leaksValueFragment(run.encoded), "the encoded batch shipped the value")
		}
	}
}

// CRS decodes ARGS with '+' as a space, so WAF text holds a managed value with
// a space in place of its '+'.
func TestManagedHeaderPrivacyPlusValueInFindingText(t *testing.T) {
	pairs := []managedHeaderCredential{{Name: "X-Partner-Key", Value: "Partner+Key/7f3a9c!"}}
	run := runPrivacyPipeline(t, privacyRunOptions{
		pairs:  pairs,
		rules:  `SecRule ARGS:api_key "@rx ." "id:900142,phase:2,pass,log,msg:'key',logdata:'%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'"`,
		target: "/search?api_key=Partner+Key%2F7f3a9c%21",
	})
	require.Len(t, run.detections, 1)
	require.True(t, run.detections[0].MatchData == managedHeaderMaskedText, "WAF match_data shipped the value with '+' decoded: %q", hidden(run.detections[0].MatchData))
	require.True(t, run.detections[0].RuleMsg == "key", "a text without a managed value was masked")
	require.False(t, leaksValueFragment(run.encoded), "the encoded batch shipped the value")
}

// legacyURLTextCarries is urlTextCarries as it was before the token scan was
// limited to short values: every managed value length is scanned as a token
// (a short value's '+' also matching a space).
func legacyURLTextCarries(p *managedHeaderPolicy, text string, all bool) bool {
	var lengths []int
	for n, set := range p.valueLens {
		if set {
			lengths = append(lengths, n)
		}
	}
	tokens := func(t string) bool {
		if p.formCarries(trimSpace(t)) || p.ipTokenCarries(t) {
			return true
		}
		for i := 0; i < len(t); i++ {
			if i > 0 && isAlnum(t[i-1]) && isAlnum(t[i]) {
				continue
			}
			for _, n := range lengths {
				end := i + n
				if end > len(t) {
					break
				}
				_, ok := p.values[foldASCII(t[i:end])]
				if _, plus := p.plusTokens[foldASCII(t[i:end])]; !ok && !plus {
					continue
				}
				if end < len(t) && isAlnum(t[end-1]) && isAlnum(t[end]) {
					continue
				}
				return true
			}
		}
		return false
	}
	t := text
	for round := 0; ; round++ {
		if p.contain.find(t) || all && tokens(t) {
			return true
		}
		if round == 3 || !strings.ContainsAny(t, "%+&\x00") {
			return false
		}
		next := decodeManagedHeaderEscapes(t)
		if next == t {
			return false
		}
		t = next
	}
}

// Scanning only values shorter than the contain threshold as tokens finds
// exactly what scanning every length did.
func TestManagedHeaderPrivacyShortTokenScanMatchesLegacy(t *testing.T) {
	rng := rand.New(rand.NewSource(20261010))
	const alphabet = "ab1Z-/.%+&=?;: "
	randomText := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(b)
	}
	encode := func(s string) string {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			switch rng.Intn(4) {
			case 0:
				fmt.Fprintf(&b, "%%%02X", s[i])
			case 1:
				fmt.Fprintf(&b, "%%u00%02x", s[i])
			default:
				b.WriteByte(s[i])
			}
		}
		return b.String()
	}
	hits := 0
	for iter := 0; iter < 3000; iter++ {
		var pairs []managedHeaderCredential
		var values []string
		for i := rng.Intn(6) + 1; i > 0; i-- {
			v := strings.TrimSpace(randomText(rng.Intn(14) + 1))
			if v == "" || strings.ContainsAny(v, ",") {
				continue
			}
			values = append(values, v)
			pairs = append(pairs, managedHeaderCredential{Name: fmt.Sprintf("X-K-%d", i), Value: v})
		}
		if len(pairs) == 0 {
			continue
		}
		policy := compileManagedHeaderPolicy(pairs)
		for j := 0; j < 20; j++ {
			var b strings.Builder
			for k := rng.Intn(6); k >= 0; k-- {
				if rng.Intn(2) == 0 {
					v := values[rng.Intn(len(values))]
					if rng.Intn(2) == 0 {
						v = encode(v)
					}
					b.WriteString(v)
				} else {
					b.WriteString(randomText(rng.Intn(8)))
				}
			}
			text := b.String()
			for _, all := range []bool{false, true} {
				want := legacyURLTextCarries(policy, text, all)
				if want {
					hits++
				}
				require.True(t, policy.urlTextCarries(text, all) == want, "urlTextCarries(%q, %v) != legacy %v (values %q)", text, all, want, values)
			}
		}
	}
	require.Greater(t, hits, 10000, "the differential rarely exercised a match")
}

// diverseLengthPairs are n managed values of n distinct lengths.
func diverseLengthPairs(n int) []managedHeaderCredential {
	pairs := make([]managedHeaderCredential, n)
	for i := range pairs {
		v := fmt.Sprintf("partner-secret-%03d-", i)
		for len(v) < 8+i*7 && len(v) < managedHeaderValueMaxBytes {
			v += "x"
		}
		pairs[i] = managedHeaderCredential{Name: fmt.Sprintf("X-Partner-Key-%03d", i), Value: v}
	}
	return pairs
}

// An adversarial carrying request: a 7.2 KB path in which every byte starts a
// token, against 128 values of distinct lengths.
func BenchmarkManagedHeaderPrivacyLongPathDistinctLengths(b *testing.B) {
	pairs := diverseLengthPairs(128)
	policy := compileManagedHeaderPolicy(pairs)
	for _, path := range []struct{ name, p string }{
		{"dashes", "/" + strings.Repeat("-", 7200)},
		{"dashes_pct", "/%2D" + strings.Repeat("-", 7200)},
	} {
		b.Run(path.name, func(b *testing.B) {
			r := httptest.NewRequest("GET", path.p, nil)
			r, _ = withDefenseSnapshotHolder(r)
			r.Header.Set(pairs[64].Name, pairs[64].Value)
			requestDefenseHolder(r).capturePrivacy(policy, r.Header)
			state := requestManagedHeaderState(r)
			if !state.masked.Load() {
				b.Fatal("the request does not carry a managed value")
			}
			uri := r.URL.String()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = telemetryPath(r)
				_ = privateCorazaURI(state, 1, uri)
			}
		})
	}
}

// OWASP CRS 4.10.0 rules 930100 and 930110, verbatim except for tags and
// anomaly scoring: their finding text quotes the raw, still-encoded URI.
const crs930100 = `SecRule REQUEST_URI_RAW|ARGS|REQUEST_HEADERS|!REQUEST_HEADERS:Referer|FILES|XML:/* "@rx (?i)(?:[/\x5c]|%(?:2(?:f|5(?:2f|5c|c(?:1%259c|0%25af))|%46)|5c|c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|(?:bg%q|(?:e|f(?:8%8)?0%8)0%80%a)f|u(?:221[56]|EFC8|F025|002f)|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|1u)|0x(?:2f|5c))(?:\.(?:%0[01]|\?)?|\?\.?|%(?:2(?:(?:5(?:2|c0%25a))?e|%45)|c0(?:\.|%[256aef]e)|u(?:(?:ff0|002)e|2024)|%32(?:%(?:%6|4)5|E)|(?:e|f(?:(?:8|c%80)%8)?0%8)0%80%ae)|0x2e){2,3}(?:[/\x5c]|%(?:2(?:f|5(?:2f|5c|c(?:1%259c|0%25af))|%46)|5c|c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|(?:bg%q|(?:e|f(?:8%8)?0%8)0%80%a)f|u(?:221[56]|EFC8|F025|002f)|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|1u)|0x(?:2f|5c))" "id:930100,phase:2,pass,log,capture,t:none,msg:'Path Traversal Attack (/../) or (/.../)',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',severity:'CRITICAL'"
SecRule REQUEST_URI|ARGS|REQUEST_HEADERS|!REQUEST_HEADERS:Referer|FILES|XML:/* "@rx (?:(?:^|[\x5c/;])\.{2,3}[\x5c/;]|[\x5c/;]\.{2,3}(?:[\x5c/;]|$))" "id:930110,phase:2,pass,log,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,t:cmdLine,msg:'Path Traversal Attack (/../) or (/.../)',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',severity:'CRITICAL',multiMatch"`

// WAF finding text on a request that carries no managed value is masked when
// the value appears in it only URL-encoded.
func TestManagedHeaderPrivacyEncodedValueInFindingText(t *testing.T) {
	pairs := []managedHeaderCredential{{Name: "X-Partner-Key", Value: "Partner-Key-7f3a9c!"}}
	run := runPrivacyPipeline(t, privacyRunOptions{pairs: pairs, rules: crs930100, target: "/keys/Partner-Key-7f3a9c%21/../../etc/passwd"})
	ids := map[uint32]bool{}
	for _, d := range run.detections {
		ids[d.RuleID] = true
		require.False(t, leaksValueFragment(d.MatchData), "rule %d match_data shipped the value: %q", d.RuleID, hidden(d.MatchData))
		require.False(t, leaksValueFragment(d.RuleMsg), "rule %d msg shipped the value", d.RuleID)
		require.False(t, leaksValueFragment(d.RequestURI), "rule %d request_uri shipped the value", d.RuleID)
	}
	require.True(t, ids[930100] && ids[930110], "the CRS path traversal rules did not both match: %v", ids)
	require.False(t, leaksValueFragment(run.encoded), "the encoded batch shipped the value")
}

// A value holding a literal '?' sent raw is split between the path and the
// query; neither half reaches telemetry.
func TestManagedHeaderPrivacyQuestionMarkValueInURL(t *testing.T) {
	pairs := []managedHeaderCredential{{Name: "X-Partner-Key", Value: "Part?ner-Key-7f3a9c"}}
	for _, carried := range []bool{false, true} {
		o := privacyRunOptions{pairs: pairs, rules: `SecRule REQUEST_HEADERS:Accept "@rx ." "id:900143,phase:1,pass,log"`, target: "/keys/Part?ner-Key-7f3a9c"}
		if carried {
			o.prepare = setHeader("X-Partner-Key", "Part?ner-Key-7f3a9c")
		}
		run := runPrivacyPipeline(t, o)
		require.Len(t, run.detections, 1)
		require.Len(t, run.events, 1)
		require.True(t, run.detections[0].RequestURI == "/keys/[masked]?[masked]", "carried=%v request_uri = %q", carried, hidden(run.detections[0].RequestURI))
		require.True(t, run.events[0].Path == "/keys/[masked]", "carried=%v request_events.path = %q", carried, hidden(run.events[0].Path))
		require.False(t, containsFold(run.encoded, "Part?ner") || containsFold(run.encoded, "/Part\"") || leaksValueFragment(run.encoded), "carried=%v the encoded batch shipped part of the value", carried)
	}
	policy := compileManagedHeaderPolicy([]managedHeaderCredential{
		{Name: "X-Partner-Key", Value: "Part?ner-Key-7f3a9c"},
		{Name: "X-Dir-Key", Value: "dir/Pa?rt-Key-7f3a9c&x=1"},
	})
	for _, tc := range []struct {
		uri     string
		carried bool
		want    string
	}{
		{"/a/Part?ner-Key-7f3a9c&b=1", false, "/a/[masked]?[masked]&b=1"},
		{"/a/Part?ner-Key-7f3a9c&b=1", true, "/a/[masked]?[masked]"},
		{"/a/Part?b=1&k=Part?ner-Key-7f3a9c", false, "/a/Part?b=1&[masked]"},
		{"/a/Part?b=1", false, "/a/Part?b=1"},
		{"/x/dir/Pa?rt-Key-7f3a9c&x=1&y=2", false, "/[masked]?[masked]"},
		{"/x/dir/Pa?rt-Key-7f3a9c&x=1&y=2", true, "/[masked]?[masked]"},
	} {
		got := policy.redactURI(tc.uri, tc.carried)
		require.True(t, got == tc.want, "redactURI(%q, %v) = %q, want %q", hidden(tc.uri), tc.carried, hidden(got), hidden(tc.want))
	}
}

// A path longer than the redaction scan window is recorded as its scanned
// window: a managed value past the window, which the scan never saw, must not
// reach path_bucket (which reads segments past the kept bytes), and a segment
// the window cuts past the kept bytes may be a value's prefix.
func TestManagedHeaderPrivacyPathBeyondScanWindow(t *testing.T) {
	const secret = "mysupersecretapikey"
	policy := compileManagedHeaderPolicy([]managedHeaderCredential{{Name: "X-Api-Key", Value: secret}})
	window := requestEventPathMaxBytes + 6*managedHeaderValueMaxBytes
	pad := func(n int) string { return "/" + strings.Repeat("a", n-1) }
	for _, target := range []string{
		pad(7200) + "/" + secret + "/x",
		strings.Repeat("/", 7200) + secret,
		pad(7200) + "/mysupersecret%61pikey/x",
		pad(window-10) + "/" + secret + "/x", // the window cuts the value
		pad(window-1) + "/" + secret,         // the window ends just after a '/'
		pad(window-70) + "/" + strings.Repeat("Q", 60) + secret + "/x",
	} {
		for _, carried := range []bool{false, true} {
			r := httptest.NewRequest("GET", target, nil)
			r, _ = withDefenseSnapshotHolder(r)
			requestDefenseHolder(r).capturePrivacy(policy, r.Header)
			requestManagedHeaderState(r).masked.Store(carried)
			got := telemetryPath(r)
			bucket := pathBucket(got)
			require.False(t, containsFold(bucket, "mysup") || containsFold(capPath(got), "mysup"),
				"carried=%v a %d-byte path shipped part of a value past the scan window: bucket %q", carried, len(target), bucket)
			require.LessOrEqual(t, len(got), window+len(managedHeaderMaskedURLPart))
		}
	}
	// An ordinary long path's bucket reflects only the scanned window.
	for _, tc := range []struct{ path, bucket string }{
		{"/" + strings.Repeat("a", 7200) + "/b/c", "/*"},
		{pad(window-5) + "/b/c", "/*/b/c"},
		{pad(window-3) + "/abcdef/c", "/*/[masked]"},
		{"/a/b/c/" + strings.Repeat("d", 7200), "/a/b/c"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = tc.path
		r, _ = withDefenseSnapshotHolder(r)
		requestDefenseHolder(r).capturePrivacy(policy, r.Header)
		require.Equal(t, tc.bucket, pathBucket(telemetryPath(r)))
	}
	// A path within the window is recorded whole.
	inWindow := pad(window-7) + "/b/c/d"
	r := httptest.NewRequest("GET", "/", nil)
	r.URL.Path = inWindow
	r, _ = withDefenseSnapshotHolder(r)
	requestDefenseHolder(r).capturePrivacy(policy, r.Header)
	require.True(t, telemetryPath(r) == inWindow)
	// The cost is bounded by the window, not the path.
	r.URL.Path = strings.Repeat("/", 16<<20)
	require.Equal(t, window, len(telemetryPath(r)))
}

// An ordinary request's query is not scanned for telemetryPath unless a value
// holds a '?' (the only way a value reaches the path from the query).
func TestManagedHeaderPrivacyTelemetryPathSkipsQueryScan(t *testing.T) {
	policy := compileManagedHeaderPolicy(benchPrivacyPairs(8))
	r := httptest.NewRequest("GET", "/products/12345?utm_source=google&q=red+shoes&r=https%3A%2F%2Fa.example%2F", nil)
	r, _ = withDefenseSnapshotHolder(r)
	requestDefenseHolder(r).capturePrivacy(policy, r.Header)
	allocs := testing.AllocsPerRun(100, func() { _ = telemetryPath(r) })
	require.Zero(t, allocs, "telemetryPath scanned the query of an ordinary request")
	require.Equal(t, "/products/12345", telemetryPath(r))
}

// A short value's '+' also matches a space as a whole token, as CRS decodes it.
func TestManagedHeaderPrivacyShortPlusValueToken(t *testing.T) {
	policy := compileManagedHeaderPolicy([]managedHeaderCredential{{Name: "X-Key", Value: "a+b/c"}})
	for _, tc := range []struct {
		uri     string
		carried bool
		want    string
	}{
		{"/x/a+b%2Fc/y", true, "/x/[masked]/y"},
		{"/x/a%2Bb%2Fc/y", true, "/x/[masked]/y"},
		{"/x/a%20b%252Fc/y", true, "/x/[masked]/y"},
		{"/x/a+b%2Fc/y", false, "/x/a+b%2Fc/y"},
		{"/x/a+b%2Fcd/y", true, "/x/a+b%2Fcd/y"},
	} {
		got := policy.redactURI(tc.uri, tc.carried)
		require.Equal(t, tc.want, got, "redactURI(%q, %v)", tc.uri, tc.carried)
	}
	// Header matching is unchanged: a field holding a space for the '+' is not the value.
	require.False(t, policy.fieldCarries("a b/c"))
	require.True(t, policy.fieldCarries("a+b/c"))
}

// A long value encoded over two rounds (eight bytes per byte) can start in the
// kept bytes and end past the scan window; the part the window cuts is masked.
func TestManagedHeaderPrivacyMultiRoundValueStraddlingScanWindow(t *testing.T) {
	value := strings.Repeat("Zq7f3a9cX", 114)[:managedHeaderValueMaxBytes]
	policy := compileManagedHeaderPolicy([]managedHeaderCredential{{Name: "X-Partner-Key", Value: value}})
	var enc strings.Builder
	for i := 0; i < len(value); i++ {
		fmt.Fprintf(&enc, "%%25u00%02x", value[i])
	}
	decodes := func(s string) bool {
		for round := 0; round <= 3; round++ {
			if strings.Contains(s, value[:64]) {
				return true
			}
			s = decodeManagedHeaderEscapes(s)
		}
		return false
	}
	for _, carried := range []bool{false, true} {
		state := newManagedHeaderState(policy, nil)
		state.masked.Store(carried)
		for _, uri := range []string{"/s?k=" + enc.String(), "/" + enc.String(), "/s?a=1&k=" + enc.String()} {
			shipped := ownedTruncate(privateCorazaURI(state, 1, uri), corazaRequestURIMaxBytes)
			require.False(t, decodes(shipped), "carried=%v request_uri shipped part of a value cut by the scan window", carried)
		}
		// request_events.path: Go decodes the path once, leaving %25u00XX.
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = "/x/" + enc.String()
		r, _ = withDefenseSnapshotHolder(r)
		requestDefenseHolder(r).capturePrivacy(policy, http.Header{})
		requestManagedHeaderState(r).masked.Store(carried)
		shipped := capPath(telemetryPath(r))
		require.False(t, decodes(shipped), "carried=%v request_events.path shipped part of a value cut by the scan window", carried)
		require.True(t, shipped == "/x/[masked]", "carried=%v the cut segment was not masked", carried)
	}
	// A long segment without escapes cut by the window is kept: no value
	// overlapping the kept bytes can end past it.
	plain := "/" + strings.Repeat("b", 9000)
	require.True(t, privateCorazaURI(newManagedHeaderState(policy, nil), 1, plain) == plain[:corazaRequestURIMaxBytes+6*managedHeaderValueMaxBytes])
}
