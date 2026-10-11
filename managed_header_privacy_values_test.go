package apxstats

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/stretchr/testify/require"
)

// The managed value under test. Assertions never print it: they use
// require.True with fixed messages, never Equal/Contains diffs.
const valuesSecret = "Partner-Key-7f3a9c!"

const valuesBrowserUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"

var valuesWriterSeq atomic.Int64

// managedConnector mimics coraza-caddy's ServeHTTP with managed_header_privacy:
// a fresh 64-hex transaction ID, bound for the whole transaction and released
// only after audit logging. bind=false is a connector without the bridge.
func managedConnector(waf coraza.WAF, bridge *CorazaPrivacyBridge, bind bool) caddyhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return err
		}
		id := hex.EncodeToString(raw[:])
		if bind {
			release := bridge.Bind(id, r)
			defer release()
		}
		tx := waf.NewTransactionWithID(id)
		defer tx.Close()
		defer tx.ProcessLogging()
		tx.ProcessConnection("203.0.113.7", 41234, "", 0)
		tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
		for name, values := range r.Header {
			for _, value := range values {
				tx.AddRequestHeader(name, value)
			}
		}
		tx.AddRequestHeader("Host", r.Host)
		it := tx.ProcessRequestHeaders()
		if it == nil {
			var err error
			if it, err = tx.ProcessRequestBody(); err != nil {
				return err
			}
		}
		if it != nil {
			return caddyhttp.Error(it.Status, errors.New("interruption triggered"))
		}
		return nextHandler(200).ServeHTTP(w, r)
	}
}

type privacyRun struct {
	events     []requestEventRow
	uniques    []recordedUnique
	detections []corazaDetection
	encoded    string
}

type privacyRunOptions struct {
	pairs       []managedHeaderCredential
	rules       string // SecRule lines
	auditParts  string // default ABHIJKZ
	noSignature bool   // omit the connector's privacy component signature
	unbound     bool   // connector without the privacy bridge
	target      string
	prepare     func(r *http.Request) // before the outer stats handler
	mutate      func(r *http.Request) // between capture_privacy and the WAF
}

// runPrivacyPipeline sends one request through apx_stats -> capture_privacy
// -> the managed WAF connector -> origin, then encodes every row it produced.
func runPrivacyPipeline(t *testing.T, o privacyRunOptions) privacyRun {
	t.Helper()
	collector := new(evidenceAuditCollector)
	writer := fmt.Sprintf("apx_privacy_values_%d", valuesWriterSeq.Add(1))
	plugins.RegisterAuditLogWriter(writer, func() plugintypes.AuditLogWriter { return collector })
	parts := o.auditParts
	if parts == "" {
		parts = "ABHIJKZ"
	}
	directives := "SecRuleEngine On\nSecAuditEngine On\nSecAuditLogParts " + parts + "\nSecAuditLogType " + writer + "\n" + o.rules + "\n"
	if !o.noSignature {
		directives += `SecComponentSignature "APX_MANAGED_HEADER_PRIVACY/1"` + "\n"
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	require.NoError(t, err)
	config, err := json.Marshal(map[string]any{"mode": "capture_privacy", "managed_headers": o.pairs})
	require.NoError(t, err)
	capture := evidenceHandler(t, string(config))
	app := &fakeApp{modeV2: true, hashSalt: "salt"}
	target := o.target
	if target == "" {
		target = "/products?color=blue"
	}
	r := newRequestWithReplacer("GET", target, "100", upstreamSelected("10.0.0.1:8080"))
	r.Host = "shop.example.com"
	r.RemoteAddr = "203.0.113.7:41234"
	r.Header.Set("User-Agent", valuesBrowserUA)
	r.Header.Set("Accept", "text/html,*/*;q=0.8")
	r.Header.Set("Authorization", "Bearer someone-else-entirely")
	if o.prepare != nil {
		o.prepare(r)
	}
	_ = (&StatsHandler{app: app}).ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return capture.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			if o.mutate != nil {
				o.mutate(r)
			}
			return managedConnector(waf, &CorazaPrivacyBridge{}, !o.unbound).ServeHTTP(w, r)
		}))
	}))
	run := privacyRun{events: app.reqEventSnapshot(), detections: collector.drain()}
	app.mu.Lock()
	run.uniques = append(run.uniques, app.uniques...)
	app.mu.Unlock()
	body, err := encodeBatch(42, 0, nil, nil, nil, l4IpSnap{}, nil, nil, run.detections, nil, nil, run.events)
	require.NoError(t, err)
	run.encoded = gunzipString(t, body)
	return run
}

// containsFold reports a case-insensitive match without printing either side.
func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// A Defense rule naming User-Agent or Authorization (or any other Header)
// must not mask requests that do not carry its value.
func TestManagedHeaderPrivacyOrdinaryTrafficKeepsDetail(t *testing.T) {
	rules := `SecRule REQUEST_HEADERS:User-Agent "@rx Mozilla" "id:900101,phase:1,pass,log,msg:'ua %{MATCHED_VAR}',logdata:'%{MATCHED_VAR}'"
SecRule REQUEST_HEADERS:Authorization "@rx Bearer" "id:900102,phase:1,pass,log,msg:'auth',logdata:'%{MATCHED_VAR}'"`
	for _, pair := range []managedHeaderCredential{
		{Name: "User-Agent", Value: "PartnerBot/1 key=7f3a9c-ua"},
		{Name: "Authorization", Value: "Bearer partner-7f3a9c-token"},
		{Name: "X-Partner-Key", Value: valuesSecret},
	} {
		t.Run(pair.Name, func(t *testing.T) {
			run := runPrivacyPipeline(t, privacyRunOptions{pairs: []managedHeaderCredential{pair}, rules: rules})
			require.Len(t, run.events, 1)
			require.True(t, run.events[0].UA == valuesBrowserUA, "an ordinary User-Agent was masked")
			require.Len(t, run.uniques, 1)
			require.True(t, run.uniques[0].hash == ClientHash("203.0.113.7:41234", valuesBrowserUA, "salt"), "the unique-client hash lost the ordinary User-Agent")
			require.Len(t, run.detections, 2)
			for _, d := range run.detections {
				require.True(t, d.MatchData != "" && d.MatchData != managedHeaderMaskedText, "an ordinary finding lost its match data")
				require.True(t, d.RuleMsg != "" && d.RuleMsg != managedHeaderMaskedText, "an ordinary finding lost its message")
			}
		})
	}
}

func setHeader(name, value string) func(*http.Request) {
	return func(r *http.Request) { r.Header[name] = append(r.Header[name], value) }
}

// A request that carries the managed value, in any form CRS can decode, never
// ships it, and its masked fields say so instead of looking absent.
func TestManagedHeaderPrivacyCarriedValueNeverReachesTelemetry(t *testing.T) {
	pairs := []managedHeaderCredential{{Name: "X-Partner-Key", Value: valuesSecret}}
	rules := `SecRule REQUEST_HEADERS:X-Partner-Key "@rx ." "id:900111,phase:1,pass,log,msg:'key %{MATCHED_VAR}',logdata:'%{MATCHED_VAR}'"
SecRule REQUEST_HEADERS:X-Partner-Key "@rx ." "id:900112,phase:1,pass,log,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,msg:'decoded',logdata:'%{MATCHED_VAR}'"
SecRule REQUEST_HEADERS:User-Agent "@rx Mozilla" "id:900113,phase:1,pass,log,msg:'ua',logdata:'%{MATCHED_VAR}'"`
	for _, tc := range []struct {
		name            string
		prepare, mutate func(*http.Request)
	}{
		{"exact", setHeader("X-Partner-Key", valuesSecret), nil},
		{"case_variant", setHeader("X-Partner-Key", strings.ToLower(valuesSecret)), nil},
		{"url_encoded", setHeader("X-Partner-Key", "Partner-Key-7f3a9c%21"), nil},
		{"double_url_encoded", setHeader("X-Partner-Key", "Partner-Key-7f3a9c%2521"), nil},
		{"unicode_url_encoded", setHeader("X-Partner-Key", "Partner-Key-7f3a9c%u0021"), nil},
		{"html_entity", setHeader("X-Partner-Key", "Partner-Key-7f3a9c&#33;"), nil},
		{"padded", setHeader("X-Partner-Key", " "+valuesSecret+"\t"), nil},
		{"duplicate_fields", func(r *http.Request) { r.Header["X-Partner-Key"] = []string{"wrong", valuesSecret} }, nil},
		{"noncanonical_name", setHeader("x-partner-KEY", valuesSecret), nil},
		{"late_injected", nil, setHeader("X-Partner-Key", valuesSecret)},
		{"mutated_away", setHeader("X-Partner-Key", valuesSecret), func(r *http.Request) { r.Header.Del("X-Partner-Key") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := runPrivacyPipeline(t, privacyRunOptions{pairs: pairs, rules: rules, prepare: tc.prepare, mutate: tc.mutate})
			require.NotEmpty(t, run.detections, "no findings: the masking check would be vacuous")
			for _, d := range run.detections {
				require.True(t, d.RuleMsg == managedHeaderMaskedText, "a carried value's finding message was not marked as masked")
				require.True(t, d.MatchData == managedHeaderMaskedText, "a carried value's match data was not marked as masked")
			}
			require.Len(t, run.events, 1)
			require.True(t, run.events[0].UA == valuesBrowserUA, "a User-Agent that does not carry the value was masked")
			require.True(t, run.events[0].Path == "/products", "a path without the value lost its detail")
			require.False(t, leaksValueFragment(run.encoded), "the managed value reached encoded telemetry")
		})
	}
	// The value in the URL: a carrying request masks every occurrence in the
	// path and its whole query; any request masks a path segment or query
	// parameter containing it, in any form CRS-style URL decoding reveals.
	for _, tc := range []struct {
		name, target, path, uri, maskedURI string
	}{
		{"path", "/keys/Partner-Key-7f3a9c!/rotate", "/keys/[masked]/rotate", "/keys/[masked]/rotate", ""},
		{"path_case_variant", "/keys/PARTNER-KEY-7F3A9C!/rotate", "/keys/[masked]/rotate", "/keys/[masked]/rotate", ""},
		{"path_embedded", "/keys/v1-Partner-Key-7f3a9c!.json", "/keys/[masked]", "/keys/[masked]", ""},
		{"path_url_encoded", "/keys/Partner-Key-7f3a9c%21/rotate", "/keys/[masked]/rotate", "/keys/[masked]/rotate", ""},
		{"path_fully_encoded", "/keys/%50artner-Key-%37f3a9c%21/rotate", "/keys/[masked]/rotate", "/keys/[masked]/rotate", ""},
		{"path_double_encoded", "/keys/Partner-Key-7f3a9c%2521/rotate", "/keys/[masked]/rotate", "/keys/[masked]/rotate", ""},
		{"query", "/search?q=shoes&api_key=Partner-Key-7f3a9c!", "/search", "/search?q=shoes&[masked]", "/search?[masked]"},
		{"query_url_encoded", "/search?q=shoes&api_key=Partner-Key-7f3a9c%21", "/search", "/search?q=shoes&[masked]", "/search?[masked]"},
		{"query_unicode_encoded", "/search?api_key=Partner-Key-7f3a9c%u0021&q=shoes", "/search", "/search?[masked]&q=shoes", "/search?[masked]"},
		{"query_fully_encoded", "/search?q=shoes&api_key=%50artner-Key-%37f3a9c%21", "/search", "/search?q=shoes&[masked]", "/search?[masked]"},
		{"query_double_encoded", "/search?q=shoes&api_key=Partner-Key-7f3a9c%2521", "/search", "/search?q=shoes&[masked]", "/search?[masked]"},
	} {
		for _, carried := range []bool{false, true} {
			t.Run(fmt.Sprintf("url_%s/carried=%v", tc.name, carried), func(t *testing.T) {
				o := privacyRunOptions{pairs: pairs, rules: rules, target: tc.target}
				if carried {
					o.prepare = setHeader("X-Partner-Key", valuesSecret)
				}
				run := runPrivacyPipeline(t, o)
				require.NotEmpty(t, run.detections, "no findings: the request_uri check would be vacuous")
				wantURI := tc.uri
				if carried && tc.maskedURI != "" {
					wantURI = tc.maskedURI
				}
				for _, d := range run.detections {
					require.True(t, d.RequestURI == wantURI, "request_uri was not masked to the expected shape")
				}
				require.Len(t, run.events, 1)
				require.True(t, run.events[0].Path == tc.path, "request_events.path was not masked to the expected shape")
				require.False(t, leaksValueFragment(run.encoded), "the managed value reached encoded telemetry")
			})
		}
	}
}

// leaksValueFragment reports whether text holds the managed value's fragment
// directly or after up to three rounds of CRS-style URL/HTML decoding.
func leaksValueFragment(text string) bool {
	for round := 0; round <= 3; round++ {
		if containsFold(text, "7f3a9c") {
			return true
		}
		text = decodeManagedHeaderEscapes(text)
	}
	return false
}

// Masked text is marked; text that never existed stays empty (absent).
func TestManagedHeaderPrivacyMaskedIsDistinguishableFromAbsent(t *testing.T) {
	uaValue := "PartnerBot/1 key=7f3a9c-ua"
	pairs := []managedHeaderCredential{{Name: "User-Agent", Value: uaValue}}
	rules := `SecRule REQUEST_HEADERS:Accept "@rx ." "id:900121,phase:1,pass,log"`
	for _, tc := range []struct {
		name, ua, want string
	}{
		{"managed", uaValue, managedHeaderMaskedText},
		{"managed_case_variant", strings.ToUpper(uaValue), managedHeaderMaskedText},
		{"absent", "", ""},
		{"ordinary", valuesBrowserUA, valuesBrowserUA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := runPrivacyPipeline(t, privacyRunOptions{pairs: pairs, rules: rules, prepare: func(r *http.Request) {
				r.Header.Del("User-Agent")
				if tc.ua != "" {
					r.Header.Set("User-Agent", tc.ua)
				}
			}})
			require.Len(t, run.events, 1)
			require.True(t, run.events[0].UA == tc.want, "request_events.ua did not distinguish masked from absent")
			require.Len(t, run.uniques, 1)
			require.True(t, run.uniques[0].hash == ClientHash("203.0.113.7:41234", tc.want, "salt"), "the unique-client hash did not use the recorded User-Agent")
			require.Len(t, run.detections, 1)
			// The rule has no msg or logdata: nothing existed, so nothing is marked.
			require.True(t, run.detections[0].RuleMsg == "" && run.detections[0].MatchData == "", "absent finding text was marked as masked")
			require.False(t, containsFold(run.encoded, "7f3a9c"), "the managed value reached encoded telemetry")
		})
	}
}

// A managed value of at least eight bytes masks any WAF text that contains
// it, whichever field carried it in; a short value never masks unrelated text.
func TestManagedHeaderPrivacyWAFTextContainingValueIsMasked(t *testing.T) {
	pairs := []managedHeaderCredential{{Name: "X-Partner-Key", Value: valuesSecret}, {Name: "X-Debug", Value: "on"}}
	rules := `SecRule ARGS:q "@rx ." "id:900131,phase:2,pass,log,msg:'search',logdata:'%{MATCHED_VAR}'"
SecRule REQUEST_HEADERS:Accept "@rx ." "id:900132,phase:1,pass,log,msg:'session on',logdata:'option on'"`
	run := runPrivacyPipeline(t, privacyRunOptions{pairs: pairs, rules: rules, target: "/search?q=partner-key-7f3a9c%21"})
	require.Len(t, run.detections, 2)
	for _, d := range run.detections {
		switch d.RuleID {
		case 900131:
			require.True(t, d.MatchData == managedHeaderMaskedText, "WAF text containing a managed value was not masked")
			require.True(t, d.RuleMsg == "search", "a text without a managed value was masked")
		case 900132:
			require.True(t, d.RuleMsg == "session on" && d.MatchData == "option on", "a short managed value masked unrelated text")
		}
	}
	require.Len(t, run.events, 1)
	require.True(t, run.events[0].UA == valuesBrowserUA, "a User-Agent without a managed value was masked")
}

// CF-Connecting-IP and X-Forwarded-For values never reach forwarded_ip or the
// unique-client hash when they are managed, in any textual form of the IP.
func TestManagedHeaderPrivacyForwardedIPs(t *testing.T) {
	pairs := []managedHeaderCredential{{Name: "Cf-Connecting-Ip", Value: "198.51.100.23"}, {Name: "X-Forwarded-For", Value: "2001:DB8::17"}}
	for _, tc := range []struct {
		name, cf, xff, forwarded, hashIP, frontProxy string
	}{
		{"cf_managed", "198.51.100.23", "", managedHeaderMaskedIP, "203.0.113.7:41234", "cloudflare"},
		{"xff_managed_list", "", "203.0.113.5, 2001:db8::17", managedHeaderMaskedIP, "203.0.113.7:41234", "forwarded"},
		{"xff_managed_other_form", "", "2001:db8:0:0::17", managedHeaderMaskedIP, "203.0.113.7:41234", "forwarded"},
		{"xff_ordinary", "", "198.51.100.99", "198.51.100.99", "198.51.100.99", "forwarded"},
		{"cf_ordinary", "198.51.100.98", "", "198.51.100.98", "203.0.113.7:41234", "cloudflare"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := runPrivacyPipeline(t, privacyRunOptions{pairs: pairs, rules: `SecRule REQUEST_HEADERS:Accept "@rx ." "id:900141,phase:1,pass,nolog"`, prepare: func(r *http.Request) {
				if tc.cf != "" {
					r.Header.Set("CF-Connecting-IP", tc.cf)
				}
				if tc.xff != "" {
					r.Header.Set("X-Forwarded-For", tc.xff)
				}
			}})
			require.Len(t, run.events, 1)
			require.True(t, run.events[0].ForwardedIP == tc.forwarded, "forwarded_ip did not mask exactly the managed IP")
			require.True(t, run.events[0].FrontProxy == tc.frontProxy, "front_proxy changed")
			require.Len(t, run.uniques, 1)
			require.True(t, run.uniques[0].hash == ClientHash(tc.hashIP, valuesBrowserUA, "salt"), "the unique-client hash used a managed IP")
			require.False(t, containsFold(run.encoded, "198.51.100.23") || containsFold(run.encoded, "2001:db8::17"), "a managed IP reached encoded telemetry")
		})
	}
}

// Long-lived transactions (WebSockets hold theirs for the connection) must
// not degrade the masking decision for any other request.
func TestManagedHeaderPrivacyLongLivedBindingsDoNotDegradeOthers(t *testing.T) {
	bridge := &CorazaPrivacyBridge{}
	ordinary := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "long-lived-key!"}}, http.Header{"Accept": {"*/*"}})
	carrying := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "long-lived-key!"}}, http.Header{"X-Key": {"long-lived-key!"}})
	var releases []func()
	for i := 0; i < 5000; i++ {
		releases = append(releases, bridge.Bind(fmt.Sprintf("long-lived-%064d", i), ordinary))
	}
	release := bridge.Bind("long-lived-new-ordinary", ordinary)
	require.True(t, bridge.Redact("long-lived-new-ordinary", "ordinary finding") == "ordinary finding", "long-lived bindings masked a new ordinary request")
	release()
	release = bridge.Bind("long-lived-new-carrying", carrying)
	require.True(t, bridge.Redact("long-lived-new-carrying", "ordinary finding") == "", "a carrying request was not masked")
	release()
	for _, release := range releases {
		release()
	}
	require.True(t, bridge.Redact("long-lived-0000000000000000000000000000000000000000000000000000000000000000", "x") == "", "a released binding kept its state")
	require.Zero(t, privacyRegistrySize(), "released bindings leaked registry entries")
}

// A transaction the connector bound must never ship raw text, even when the
// WAF's audit log omitted part H (no privacy proof in the producer).
func TestCorazaWriterMasksBoundTransactionsWithoutPrivacyProof(t *testing.T) {
	pairs := []managedHeaderCredential{{Name: "X-Partner-Key", Value: valuesSecret}}
	rules := `SecRule REQUEST_HEADERS:X-Partner-Key "@rx ." "id:900151,phase:1,pass,log,msg:'key %{MATCHED_VAR}',logdata:'%{MATCHED_VAR}'"
SecRule REQUEST_HEADERS:Accept "@rx ." "id:900152,phase:1,pass,log,msg:'accept',logdata:'%{MATCHED_VAR}'"`
	for _, parts := range []string{"ABIJKZ", "ABHIJKZ"} {
		for _, signature := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/signature=%v", parts, signature), func(t *testing.T) {
				run := runPrivacyPipeline(t, privacyRunOptions{pairs: pairs, rules: rules, auditParts: parts, noSignature: !signature, prepare: setHeader("X-Partner-Key", valuesSecret)})
				require.Len(t, run.detections, 2)
				for _, d := range run.detections {
					require.True(t, d.RuleMsg == managedHeaderMaskedText && d.MatchData == managedHeaderMaskedText, "a bound transaction shipped raw text")
				}
				require.False(t, containsFold(run.encoded, "7f3a9c"), "the managed value reached encoded telemetry")
				ordinary := runPrivacyPipeline(t, privacyRunOptions{pairs: pairs, rules: rules, auditParts: parts, noSignature: !signature})
				require.Len(t, ordinary.detections, 1)
				require.True(t, ordinary.detections[0].MatchData == "text/html,*/*;q=0.8", "a bound ordinary transaction lost its detail")
			})
		}
	}
	// Teeth for the fixtures: without the bridge the same rules do echo it.
	raw := runPrivacyPipeline(t, privacyRunOptions{pairs: pairs, rules: rules, auditParts: "ABIJKZ", noSignature: true, unbound: true, prepare: setHeader("X-Partner-Key", valuesSecret)})
	require.True(t, containsFold(raw.encoded, "7f3a9c"), "fixture rules no longer echo the Header; the masking checks are vacuous")
}

// Configuration and state never print managed values.
func TestManagedHeaderPrivacyFormattingRedactsValues(t *testing.T) {
	pairs := []managedHeaderCredential{{Name: "X-Partner-Key", Value: valuesSecret}}
	config, err := json.Marshal(map[string]any{"mode": "capture_privacy", "managed_headers": pairs})
	require.NoError(t, err)
	handler := evidenceHandler(t, string(config))
	r := privacyRequest(t, pairs, http.Header{"X-Partner-Key": {valuesSecret}})
	for _, value := range []any{handler, pairs, pairs[0], requestDefenseHolder(r)} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			require.False(t, containsFold(fmt.Sprintf(verb, value), "7f3a9c"), "formatting printed a managed value")
		}
	}
}

// A token managed under another Header masks a User-Agent that embeds it; a
// User-Agent rule value masks only a whole User-Agent, so a rule on a common
// prefix leaves every browser's User-Agent intact.
func TestManagedHeaderPrivacyUserAgentEmbeddingAndCommonPrefix(t *testing.T) {
	pairs := []managedHeaderCredential{{Name: "X-Partner-Key", Value: valuesSecret}, {Name: "User-Agent", Value: "Mozilla/5.0"}}
	for _, tc := range []struct {
		name, ua, want string
	}{
		{"embedded_partner_token", "PartnerBot/2 (token=partner-key-7F3A9C!)", managedHeaderMaskedText},
		{"browser_with_common_prefix", valuesBrowserUA, valuesBrowserUA},
		{"bare_rule_value", "Mozilla/5.0", managedHeaderMaskedText},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := runPrivacyPipeline(t, privacyRunOptions{pairs: pairs, rules: `SecRule REQUEST_HEADERS:Accept "@rx ." "id:900161,phase:1,pass,nolog"`, prepare: func(r *http.Request) { r.Header.Set("User-Agent", tc.ua) }})
			require.Len(t, run.events, 1)
			require.True(t, run.events[0].UA == tc.want, "request_events.ua did not follow the User-Agent rule scope")
			require.False(t, containsFold(run.encoded, "7f3a9c"), "the managed value reached encoded telemetry")
		})
	}
}

// URL redaction keeps the URL's shape: segments and parameters carrying a
// managed value become the marker, a value spanning them masks the whole part,
// and short values mask only whole tokens of a carrying request.
func TestManagedHeaderPrivacyURLRedaction(t *testing.T) {
	policy := compileManagedHeaderPolicy([]managedHeaderCredential{
		{Name: "X-Partner-Key", Value: valuesSecret},
		{Name: "Authorization", Value: "Bearer tok/7f3a9c-slash"},
		{Name: "X-Debug", Value: "on"},
		{Name: "X-Real-Ip", Value: "2001:db8::17"},
		{Name: "Cf-Connecting-Ip", Value: "1.2.3.4"},
	})
	for _, tc := range []struct {
		name, uri string
		carried   bool
		want      string
	}{
		{"ordinary", "/a/b?c=d", false, "/a/b?c=d"},
		{"ordinary_carried_masks_query", "/a/b?c=d", true, "/a/b?[masked]"},
		{"no_query_carried", "/a/b", true, "/a/b"},
		{"value_spans_segments", "/x/Bearer%20tok/7f3a9c-slash/y", false, "/[masked]"},
		{"value_spans_parameters", "/x?a=Partner-Key-7f3a9c%21&b=1&c=Bearer+tok%2F7f3a9c-slash", false, "/x?[masked]&b=1&[masked]"},
		{"value_spans_parameters_raw", "/x?k=Bearer tok/7f3a9c-slash&b=2", false, "/x?[masked]&b=2"},
		{"short_value_unmasked_request", "/on/turn-on", false, "/on/turn-on"},
		{"short_value_whole_token_carried", "/on/turn-on/onion", true, "/[masked]/[masked]/onion"},
		{"short_value_encoded_token_carried", "/%6Fn/x", true, "/[masked]/x"},
		{"managed_ip_other_form_carried", "/ip/2001:db8:0:0::17", true, "/ip/[masked]"},
		{"managed_ipv4_after_hex_letters_carried", "/ip/abc1.2.3.4", true, "/ip/[masked]"},
		{"managed_ip_unmasked_request", "/ip/2001:db8:0:0::17", false, "/ip/2001:db8:0:0::17"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := policy.redactURI(tc.uri, tc.carried)
			require.True(t, got == tc.want, "redactURI(%q, %v) = %q, want %q", strings.ReplaceAll(tc.uri, "7f3a9c", "…"), tc.carried, strings.ReplaceAll(got, "7f3a9c", "…"), tc.want)
		})
	}
	// The marker never carries a managed value itself.
	clash := compileManagedHeaderPolicy([]managedHeaderCredential{{Name: "X-Key", Value: "masked"}, {Name: "X-Key", Value: "*"}})
	require.True(t, clash.redactURI("/masked/x?q=1", true) == "/-/x?-", "a marker that carries a managed value was used")
	// A value straddling the truncation limit is redacted before truncation.
	long := "/" + strings.Repeat("a", corazaRequestURIMaxBytes-10) + "/" + valuesSecret + "/" + strings.Repeat("b", 9000)
	shipped := ownedTruncate(privateCorazaURI(newManagedHeaderState(policy, nil), 1, long), corazaRequestURIMaxBytes)
	require.False(t, containsFold(shipped, "partner-key"), "a value straddling the truncation limit was partly shipped")
	require.True(t, strings.HasSuffix(shipped, "/[masked]/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"[:len(shipped)-corazaRequestURIMaxBytes+9]), "the straddling value was not replaced by the marker")
	// Without a state (unbound or reused transaction) the whole target is masked.
	require.True(t, privateCorazaURI(nil, 1, "/a?b") == "/[masked]")
}
