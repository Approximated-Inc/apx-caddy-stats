package apxstats

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/stretchr/testify/require"
)

// OWASP CRS 4.10.0 rule 920274 (paranoia level 4, the strictest Header byte
// range), verbatim except that it denies and logs on its own.
const crs920274 = `SecRule REQUEST_HEADERS|!REQUEST_HEADERS:User-Agent|!REQUEST_HEADERS:Referer|!REQUEST_HEADERS:Cookie|!REQUEST_HEADERS:Sec-Fetch-User|!REQUEST_HEADERS:Sec-CH-UA|!REQUEST_HEADERS:Sec-CH-UA-Mobile "@validateByteRange 32,34,38,42-59,61,65-90,95,97-122" "id:920274,phase:1,deny,status:403,log,auditlog,t:none,t:urlDecodeUni,msg:'Invalid character in request headers (outside of very strict set)',logdata:'%{MATCHED_VAR_NAME}=%{MATCHED_VAR}',severity:'CRITICAL'"`

// A current Chrome navigation, as coraza-caddy hands it to the WAF.
var crsBrowserHeaders = [][2]string{
	{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"},
	{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
	{"Accept-Language", "en-US,en;q=0.9"},
	{"Accept-Encoding", "gzip, deflate, br, zstd"},
	{"Sec-Ch-Ua", `"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"`},
	{"Sec-Ch-Ua-Mobile", "?0"},
	{"Sec-Ch-Ua-Platform", `"macOS"`},
	{"Upgrade-Insecure-Requests", "1"},
	{"Sec-Fetch-Site", "none"},
	{"Sec-Fetch-Mode", "navigate"},
	{"Sec-Fetch-User", "?1"},
	{"Sec-Fetch-Dest", "document"},
	{"Priority", "u=0, i"},
	{"X-Apx-Vhost-Id", "100"},
}

// crsWAFDirectives mirrors Approximated.Coraza.build_directives/1 for one
// cluster in block mode with Defense evidence v2. ruleset is "crs-pl1" (what
// production runs: the PL1-only subset, paranoia forced to 1, no response
// bodies) or "crs" at paranoia level pl, from root (the app's vendored
// fly/coraza, CRS 4.10.0). Without root it runs 920274 alone.
func crsWAFDirectives(root, ruleset string, pl int, writer string) string {
	var b strings.Builder
	if root != "" {
		fmt.Fprintf(&b, "Include %s/coraza.conf\nInclude %s/crs-setup.conf\n", root, root)
		fmt.Fprintf(&b, `SecAction "id:9100,phase:1,nolog,pass,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d"`+"\n", pl, pl)
	}
	b.WriteString(`SecRule REQUEST_HEADERS:X-Apx-Coraza-Observe "@streq true" "id:9500003,phase:1,nolog,pass,t:none,ctl:ruleEngine=DetectionOnly"` + "\n")
	b.WriteString(`SecRule REQUEST_HEADERS:X-Apx-Coraza-Skip-942100 "@streq true" "id:9600001,phase:1,nolog,pass,t:none,ctl:ruleRemoveById=942100"` + "\n")
	switch {
	case root == "":
		b.WriteString(crs920274 + "\n")
	case ruleset == "crs-pl1":
		fmt.Fprintf(&b, "Include %s/crs-pl1/*.conf\nSecResponseBodyAccess Off\n", root)
	default:
		fmt.Fprintf(&b, "Include %s/crs/*.conf\n", root)
	}
	b.WriteString("SecRuleEngine On\n" + `SecComponentSignature "APX_DEFENSE_EVIDENCE/2"` + "\n")
	fmt.Fprintf(&b, "SecAuditEngine On\nSecAuditLogParts ABHIJKZ\nSecAuditLogType %s\n", writer)
	return b.String()
}

// A normal browser GET carrying the stamped evidence Headers (including the
// longest marker the selector catalog allows) stays clean in block mode: under
// production's crs-pl1 ruleset first, then the full CRS at PL1-PL4.
func TestDefenseEvidenceStampedHeadersAreCRSClean(t *testing.T) {
	type rulesetLevel struct {
		ruleset string
		pl      int
	}
	root := os.Getenv("APX_CRS_ROOT")
	cases := []rulesetLevel{{"920274", 4}}
	if root != "" {
		setup, err := os.ReadFile(filepath.Join(root, "crs-setup.conf"))
		require.NoError(t, err)
		require.Contains(t, string(setup), "OWASP_CRS/4.10.0")
		cases = []rulesetLevel{{"crs-pl1", 1}, {"crs", 1}, {"crs", 2}, {"crs", 3}, {"crs", 4}}
	}
	collector := new(evidenceAuditCollector)
	plugins.RegisterAuditLogWriter("apx_stamped_crs", func() plugintypes.AuditLogWriter { return collector })
	full, fullVars := []string{}, caddyhttp.VarsMiddleware{"e_http": "true", "e_skip": "true"}
	for _, id := range defenseCRSIDs {
		full = append(full, fmt.Sprintf(`"%d":"e_rule_%d"`, id, id))
		fullVars[fmt.Sprintf("e_rule_%d", id)] = "true"
	}
	capture := evidenceHandler(t, `{"mode":"capture","http_var":"e_http","coraza_all_var":"e_all","observe_coraza_var":"e_observe","skip_coraza_rule_vars":{"942100":"e_skip"},"coraza_rule_vars":{`+strings.Join(full, ",")+`}}`)
	stamp := evidenceHandler(t, `{"mode":"stamp_waf"}`)
	for _, tc := range cases {
		pl := tc.pl
		t.Run(fmt.Sprintf("%s/PL%d", tc.ruleset, pl), func(t *testing.T) {
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(crsWAFDirectives(root, tc.ruleset, pl, "apx_stamped_crs")))
			require.NoError(t, err)
			var status int
			var stamped string
			r := newRequestWithReplacer("GET", "/products/blue-shirt?color=blue", "100", nil)
			r.Host = "shop.example.com"
			for _, h := range crsBrowserHeaders {
				r.Header.Set(h[0], h[1])
			}
			err = (&StatsHandler{app: &fakeApp{modeV2: true}}).ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return fullVars.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					return capture.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
						return stamp.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
							stamped = r.Header.Get(defenseEvidenceHeader)
							return corazaCaddyWAF(waf, &status).ServeHTTP(w, r)
						}))
					}))
				}))
			}))
			ids := []uint32{}
			for _, event := range collector.drain() {
				ids = append(ids, event.RuleID)
			}
			require.True(t, len(stamped) > 7*len(defenseCRSIDs), "the longest marker was not stamped; the check would be vacuous")
			require.Equal(t, http.StatusOK, status, "PL%d blocked a normal browser GET; findings=%v", pl, ids)
			require.NoError(t, err)
			require.Empty(t, ids, "PL%d produced findings for a normal browser GET", pl)
		})
	}
}

// corazaCaddyWAF feeds a request to a WAF the way coraza-caddy's
// processRequest does, and returns its interruption as a Caddy error.
func corazaCaddyWAF(waf coraza.WAF, status *int) caddyhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		tx := waf.NewTransaction()
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
		tx.SetServerName(r.Host)
		it := tx.ProcessRequestHeaders()
		if it == nil {
			var err error
			if it, err = tx.ProcessRequestBody(); err != nil {
				return err
			}
		}
		if it != nil {
			*status = it.Status
			return caddyhttp.Error(it.Status, errors.New("interruption triggered"))
		}
		*status = http.StatusOK
		w.WriteHeader(http.StatusOK)
		return nil
	}
}
