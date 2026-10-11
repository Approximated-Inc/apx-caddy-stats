package apxstats

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

// A User-Agent that is a managed value must not reach request_events or the
// unique-client hash, in legacy and v2 rows; whichever Header name the value
// is managed under, the User-Agent carrying it is replaced by the marker.
// Any other User-Agent is recorded intact.
func TestManagedUserAgentMaskedInRequestTelemetry(t *testing.T) {
	secret := "managed-ua-value!"
	for _, modeV2 := range []bool{false, true} {
		for _, managedName := range []string{"User-Agent", "user-agent", "X-Key"} {
			for _, carries := range []bool{true, false} {
				t.Run(fmt.Sprintf("v2=%v/%s/carries=%v", modeV2, managedName, carries), func(t *testing.T) {
					app := &fakeApp{modeV2: modeV2, hashSalt: "salt"}
					h := &StatsHandler{app: app}
					defense := &DefenseEvidenceHandler{Mode: "capture_privacy", ManagedHeaders: []managedHeaderCredential{{Name: managedName, Value: secret}}}
					require.NoError(t, defense.Validate())
					next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
						return defense.ServeHTTP(w, r, nextHandler(200))
					})

					ua := "Mozilla/5.0 ordinary"
					if carries {
						ua = secret
					}
					r := newRequestWithReplacer("GET", "/", "100", upstreamSelected("10.0.0.1:8080"))
					r.RemoteAddr = "203.0.113.7:54321"
					r.Header.Set("User-Agent", ua)
					require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, next))

					evs := app.reqEventSnapshot()
					require.Len(t, evs, 1)
					require.Len(t, app.uniques, 1)
					if carries {
						require.False(t, strings.Contains(evs[0].UA, secret), "managed User-Agent stored in request_events")
						require.True(t, evs[0].UA == managedHeaderMaskedText, "managed User-Agent was not marked as masked")
						require.True(t, app.uniques[0].hash == ClientHash("203.0.113.7:54321", managedHeaderMaskedText, "salt"), "managed User-Agent fed the unique-client hash")
					} else {
						require.True(t, evs[0].UA == ua, "ordinary User-Agent was masked")
						require.True(t, app.uniques[0].hash == ClientHash("203.0.113.7:54321", ua, "salt"), "ordinary User-Agent left the unique-client hash")
					}
				})
			}
		}
	}
}
