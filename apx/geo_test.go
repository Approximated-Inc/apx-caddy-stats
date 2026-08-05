package apxapp

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

const testMMDB = "testdata/GeoLite2-City-Test.mmdb"

// provisionedApp provisions an App from raw config JSON via the real caddy
// Provision path (so geo wiring is exercised end-to-end, not just provisionGeo).
func provisionedApp(t *testing.T, rawConfig string) *App {
	t.Helper()
	var a App
	require.NoError(t, json.Unmarshal([]byte(rawConfig), &a))
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	require.NoError(t, a.Provision(ctx))
	return &a
}

func TestGeoCountryCodeFastPath(t *testing.T) {
	a := provisionedApp(t, `{"geo":{"db_path":"`+testMMDB+`"}}`)
	require.NotNil(t, a.geo)

	// Documented MaxMind-DB test IPs.
	require.Equal(t, "GB", a.GeoCountryCode(net.ParseIP("81.2.69.142")))
	require.Equal(t, "SE", a.GeoCountryCode(net.ParseIP("89.160.20.128")))
	require.Equal(t, "CN", a.GeoCountryCode(net.ParseIP("175.16.199.88")))

	// Lookup miss (private range not in the test DB) -> "".
	require.Equal(t, "", a.GeoCountryCode(net.ParseIP("10.0.0.1")))
	// Nil ip -> "".
	require.Equal(t, "", a.GeoCountryCode(nil))
}

func TestGeoEmptyDBPathDisablesLookups(t *testing.T) {
	a := provisionedApp(t, `{}`)
	require.Nil(t, a.geo)
	require.Equal(t, "", a.GeoCountryCode(net.ParseIP("81.2.69.142")))
	rec, ok := a.GeoRecord(net.ParseIP("81.2.69.142"))
	require.False(t, ok)
	require.Nil(t, rec)
}

func TestGeoMissingFileIsNotProvisionError(t *testing.T) {
	a := provisionedApp(t, `{"geo":{"db_path":"testdata/does-not-exist.mmdb"}}`)
	require.Nil(t, a.geo)
	require.Equal(t, "", a.GeoCountryCode(net.ParseIP("81.2.69.142")))
	_, ok := a.GeoRecord(net.ParseIP("81.2.69.142"))
	require.False(t, ok)
}

func TestGeoCorruptFileIsNotProvisionError(t *testing.T) {
	corrupt := filepath.Join(t.TempDir(), "corrupt.mmdb")
	require.NoError(t, os.WriteFile(corrupt, []byte("this is not an mmdb file at all"), 0o644))

	a := provisionedApp(t, `{"geo":{"db_path":"`+corrupt+`"}}`)
	require.Nil(t, a.geo)
	require.Equal(t, "", a.GeoCountryCode(net.ParseIP("81.2.69.142")))
	_, ok := a.GeoRecord(net.ParseIP("81.2.69.142"))
	require.False(t, ok)
}

func TestGeoRecordFullDecode(t *testing.T) {
	a := provisionedApp(t, `{"geo":{"db_path":"`+testMMDB+`"}}`)

	rec, ok := a.GeoRecord(net.ParseIP("81.2.69.142"))
	require.True(t, ok)
	require.NotNil(t, rec)
	require.Equal(t, "GB", rec.Country.ISOCode)
	require.Equal(t, "London", rec.City.Names["en"])
	require.Equal(t, "EU", rec.Continent.Code)
	require.Equal(t, "Europe/London", rec.Location.TimeZone)
	require.Len(t, rec.Subdivisions, 1)
	require.Equal(t, "ENG", rec.Subdivisions[0].IsoCode)

	// Boxford entry has two subdivisions in the test data.
	rec, ok = a.GeoRecord(net.ParseIP("2.125.160.216"))
	require.True(t, ok)
	require.Equal(t, "Boxford", rec.City.Names["en"])
	require.Len(t, rec.Subdivisions, 2)

	// Miss -> zero-valued record, ok=true (matches fork placeholder behavior).
	rec, ok = a.GeoRecord(net.ParseIP("10.0.0.1"))
	require.True(t, ok)
	require.Equal(t, "", rec.Country.ISOCode)
	require.Empty(t, rec.City.Names)

	// Nil ip -> not ok.
	rec, ok = a.GeoRecord(nil)
	require.False(t, ok)
	require.Nil(t, rec)
}

func TestGeoConcurrentLookups(t *testing.T) {
	a := provisionedApp(t, `{"geo":{"db_path":"`+testMMDB+`"}}`)

	ips := []struct {
		ip      net.IP
		country string
	}{
		{net.ParseIP("81.2.69.142"), "GB"},
		{net.ParseIP("89.160.20.128"), "SE"},
		{net.ParseIP("175.16.199.88"), "CN"},
		{net.ParseIP("10.0.0.1"), ""},
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				c := ips[i%len(ips)]
				if got := a.GeoCountryCode(c.ip); got != c.country {
					t.Errorf("GeoCountryCode(%s) = %q, want %q", c.ip, got, c.country)
					return
				}
				if _, ok := a.GeoRecord(c.ip); !ok {
					t.Errorf("GeoRecord(%s) not ok", c.ip)
					return
				}
			}
		}()
	}
	wg.Wait()
}
