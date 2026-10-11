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

// A managed (secret) Header named User-Agent must not reach request_events or
// the unique-client hash; other managed names leave the User-Agent intact.
func TestManagedUserAgentMaskedInRequestTelemetry(t *testing.T) {
	secret := "managed-ua-value!"
	for _, modeV2 := range []bool{false, true} {
		for _, managedName := range []string{"User-Agent", "user-agent", "X-Key"} {
			t.Run(fmt.Sprintf("v2=%v/%s", modeV2, managedName), func(t *testing.T) {
				app := &fakeApp{modeV2: modeV2, hashSalt: "salt"}
				h := &StatsHandler{app: app}
				defense := &DefenseEvidenceHandler{Mode: "capture_privacy", ManagedHeaders: []managedHeaderCredential{{Name: managedName, Value: secret}}}
				require.NoError(t, defense.Validate())
				next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					return defense.ServeHTTP(w, r, nextHandler(200))
				})

				r := newRequestWithReplacer("GET", "/", "100", upstreamSelected("10.0.0.1:8080"))
				r.RemoteAddr = "203.0.113.7:54321"
				r.Header.Set("User-Agent", secret)
				require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, next))

				evs := app.reqEventSnapshot()
				require.Len(t, evs, 1)
				require.Len(t, app.uniques, 1)
				if strings.EqualFold(managedName, "User-Agent") {
					require.False(t, strings.Contains(evs[0].UA, secret), "managed User-Agent stored in request_events")
					require.True(t, evs[0].UA == "", "managed User-Agent was not masked")
					require.True(t, app.uniques[0].hash == ClientHash("203.0.113.7:54321", "", "salt"), "managed User-Agent fed the unique-client hash")
				} else {
					require.True(t, evs[0].UA == secret, "unmanaged User-Agent was dropped")
					require.True(t, app.uniques[0].hash == ClientHash("203.0.113.7:54321", secret, "salt"), "unmanaged User-Agent left the unique-client hash")
				}
			})
		}
	}
}
