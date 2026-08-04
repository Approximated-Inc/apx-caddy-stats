package apxstats

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	apxapp "github.com/Approximated-Inc/apx-caddy-stats/apx"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

// Test DB facts (verified empirically in TestGeoProviderTestDBGroundTruth):
//
//	81.2.69.142   -> GB hit: London city, 1 subdivision (ENG), full City data
//	2.125.160.216 -> GB hit: Boxford, 2 subdivisions (ENG, WBK)
//	89.160.20.128 -> SE hit
//	10.0.0.1      -> in-DB MISS (private range): zero record, ok=true
const geoProviderTestDB = "apx/testdata/GeoLite2-City-Test.mmdb"

func geoProviderApp(t *testing.T) *apxapp.App {
	t.Helper()
	var a apxapp.App
	require.NoError(t, json.Unmarshal([]byte(`{"geo":{"db_path":"`+geoProviderTestDB+`"}}`), &a))
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	require.NoError(t, a.Provision(ctx))
	return &a
}

func geoProviderReq(remoteAddr, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	require.NotNil(t, ip, "unparseable test IP %q", s)
	return ip
}

// countGeoDecodes installs the test hook and returns a counter of full
// GeoRecord decodes. Not parallel-safe (package-global hook) — none of
// these tests call t.Parallel.
func countGeoDecodes(t *testing.T) *int {
	t.Helper()
	n := new(int)
	prev := geoDecodeTestHook
	geoDecodeTestHook = func() { *n++ }
	t.Cleanup(func() { geoDecodeTestHook = prev })
	return n
}

func TestGeoProviderTestDBGroundTruth(t *testing.T) {
	a := geoProviderApp(t)

	rec, ok := a.GeoRecord(mustIP(t, "81.2.69.142"))
	require.True(t, ok)
	require.Equal(t, "GB", rec.Country.ISOCode)
	require.Equal(t, "London", rec.City.Names["en"])
	require.Len(t, rec.Subdivisions, 1)
	require.Equal(t, "ENG", rec.Subdivisions[0].IsoCode)

	rec, ok = a.GeoRecord(mustIP(t, "2.125.160.216"))
	require.True(t, ok)
	require.Len(t, rec.Subdivisions, 2)

	require.Equal(t, "SE", a.GeoCountryCode(mustIP(t, "89.160.20.128")))

	// 10.0.0.1 is an in-DB miss: lookup succeeds, record is zero-valued.
	rec, ok = a.GeoRecord(mustIP(t, "10.0.0.1"))
	require.True(t, ok)
	require.Equal(t, "", rec.Country.ISOCode)
	require.Empty(t, rec.Subdivisions)
}

func TestGeoProviderOffModes(t *testing.T) {
	a := geoProviderApp(t)
	decodes := countGeoDecodes(t)

	for _, mode := range []string{"off", "false", "0"} {
		p := newGeoProvider(a, mode, geoProviderReq("81.2.69.142:443", ""))

		// Fixed keys keep the fork's blanket "" init: ("", true).
		for _, key := range []string{
			"geoip2.ip_address", "geoip2.country_code", "geoip2.country_eu",
			"geoip2.location_metro_code", "geoip2.subdivisions_1_iso_code",
		} {
			v, ok := p(key)
			require.True(t, ok, "mode %q key %q", mode, key)
			require.Equal(t, "", v, "mode %q key %q", mode, key)
		}

		// Dynamic and unknown keys were never Set by the fork: (nil, false).
		for _, key := range []string{
			"geoip2.country_names_en", "geoip2.subdivisions_3_iso_code",
			"geoip2.not_a_real_key",
		} {
			_, ok := p(key)
			require.False(t, ok, "mode %q key %q", mode, key)
		}

		// Non-geoip2 keys are not ours.
		_, ok := p("http.request.host")
		require.False(t, ok)
	}
	require.Equal(t, 0, *decodes)
}

// The fork's off check is exact-match on "off"/"false"/"0": empty mode means
// DEFAULT (trusted_proxies), where the lookup still runs from RemoteAddr.
func TestGeoProviderEmptyModeIsNotOff(t *testing.T) {
	a := geoProviderApp(t)
	p := newGeoProvider(a, "", geoProviderReq("81.2.69.142:443", ""))
	v, ok := p("geoip2.country_code")
	require.True(t, ok)
	require.Equal(t, "GB", v)
}

// Both observable states of a bool and of numeric keys: string "" when no
// lookup ran vs typed zero values after a lookup that MISSED the DB.
func TestGeoProviderTwoObservableStates(t *testing.T) {
	a := geoProviderApp(t)

	// State 1: mode on but client IP unparseable -> no lookup ran.
	decodes := countGeoDecodes(t)
	p := newGeoProvider(a, "wild", geoProviderReq("not-an-ip", ""))
	for _, key := range []string{
		"geoip2.country_eu",                      // bool key -> "" string
		"geoip2.location_metro_code",             // uint key -> "" string
		"geoip2.country_confidence",              // uint16 key -> "" string
		"geoip2.traits_autonomous_system_number", // uint64 key -> "" string
		"geoip2.location_latitude",               // float64 key -> "" string
		"geoip2.ip_address", "geoip2.country_code",
	} {
		v, ok := p(key)
		require.True(t, ok, key)
		require.Equal(t, "", v, key)
	}
	_, ok := p("geoip2.country_names_en")
	require.False(t, ok)
	require.Equal(t, 0, *decodes, "no-lookup state must not decode")

	// State 2: lookup ran but MISSED (10.0.0.1) -> typed zero values.
	p = newGeoProvider(a, "wild", geoProviderReq("10.0.0.1:9999", ""))
	v, ok := p("geoip2.ip_address")
	require.True(t, ok)
	require.Equal(t, "10.0.0.1", v)
	v, ok = p("geoip2.country_code")
	require.True(t, ok)
	require.Equal(t, "", v)

	v, ok = p("geoip2.country_eu")
	require.True(t, ok)
	require.Equal(t, false, v) // bool false, NOT ""
	v, ok = p("geoip2.location_metro_code")
	require.True(t, ok)
	require.Equal(t, uint(0), v)
	v, ok = p("geoip2.country_confidence")
	require.True(t, ok)
	require.Equal(t, uint16(0), v)
	v, ok = p("geoip2.traits_autonomous_system_number")
	require.True(t, ok)
	require.Equal(t, uint64(0), v)
	v, ok = p("geoip2.location_latitude")
	require.True(t, ok)
	require.Equal(t, float64(0), v)
	v, ok = p("geoip2.traits_userCount")
	require.True(t, ok)
	require.Equal(t, int32(0), v)

	// String keys stay "" and *_name keys keep their init (no "en" entry).
	v, ok = p("geoip2.country_name")
	require.True(t, ok)
	require.Equal(t, "", v)

	// Subdivision fixed keys: the fork's loop never ran on a miss, so the
	// blanket "" init survives even though the lookup ran.
	v, ok = p("geoip2.subdivisions_1_confidence")
	require.True(t, ok)
	require.Equal(t, "", v)

	// Dynamic keys remain unresolvable after a miss.
	_, ok = p("geoip2.country_names_en")
	require.False(t, ok)
}

func TestGeoProviderHitValues(t *testing.T) {
	a := geoProviderApp(t)
	rec, recOK := a.GeoRecord(mustIP(t, "81.2.69.142"))
	require.True(t, recOK)

	p := newGeoProvider(a, "wild", geoProviderReq("81.2.69.142:55555", ""))

	v, ok := p("geoip2.country_code")
	require.True(t, ok)
	require.Equal(t, "GB", v)
	v, ok = p("geoip2.ip_address")
	require.True(t, ok)
	require.Equal(t, "81.2.69.142", v)

	// Values must equal the fork's repl.Set expressions over the record.
	v, ok = p("geoip2.country_name")
	require.True(t, ok)
	require.Equal(t, rec.Country.Names["en"], v)
	v, ok = p("geoip2.country_eu")
	require.True(t, ok)
	require.Equal(t, rec.Country.IsInEuropeanUnion, v)
	v, ok = p("geoip2.country_geoname_id")
	require.True(t, ok)
	require.Equal(t, rec.Country.GeoNameID, v) // typed uint64
	v, ok = p("geoip2.city_name")
	require.True(t, ok)
	require.Equal(t, "London", v)
	v, ok = p("geoip2.location_time_zone")
	require.True(t, ok)
	require.Equal(t, "Europe/London", v)
	v, ok = p("geoip2.location_latitude")
	require.True(t, ok)
	require.Equal(t, rec.Location.Latitude, v)
	v, ok = p("geoip2.subdivisions")
	require.True(t, ok)
	require.Equal(t, rec.Subdivisions, v)

	// Subdivision 1 exists (ENG); subdivision 2 does not -> init "" survives.
	v, ok = p("geoip2.subdivisions_1_iso_code")
	require.True(t, ok)
	require.Equal(t, "ENG", v)
	v, ok = p("geoip2.subdivisions_2_iso_code")
	require.True(t, ok)
	require.Equal(t, "", v)

	// locales_en is a fixed key the fork's integer-indexed loop never writes.
	v, ok = p("geoip2.subdivisions_1_locales_en")
	require.True(t, ok)
	require.Equal(t, "", v)

	// Dynamic keys.
	v, ok = p("geoip2.country_names_en")
	require.True(t, ok)
	require.Equal(t, rec.Country.Names["en"], v)
	v, ok = p("geoip2.subdivisions_1_names_en")
	require.True(t, ok)
	require.Equal(t, rec.Subdivisions[0].Names["en"], v)
	_, ok = p("geoip2.country_names_no_such_locale")
	require.False(t, ok)
	_, ok = p("geoip2.subdivisions_3_iso_code") // only 1 subdivision
	require.False(t, ok)
	_, ok = p("geoip2.subdivisions_01_iso_code") // non-canonical index
	require.False(t, ok)
	_, ok = p("geoip2.subdivisions_1_locales_0") // Locales never decodes
	require.False(t, ok)

	// Unknown geoip2.* and non-geoip2 keys.
	_, ok = p("geoip2.not_a_real_key")
	require.False(t, ok)
	_, ok = p("http.request.host")
	require.False(t, ok)
}

func TestGeoProviderTwoSubdivisions(t *testing.T) {
	a := geoProviderApp(t)
	rec, recOK := a.GeoRecord(mustIP(t, "2.125.160.216"))
	require.True(t, recOK)
	require.Len(t, rec.Subdivisions, 2)

	p := newGeoProvider(a, "wild", geoProviderReq("2.125.160.216:1", ""))
	v, ok := p("geoip2.subdivisions_2_iso_code")
	require.True(t, ok)
	require.Equal(t, rec.Subdivisions[1].IsoCode, v)
	v, ok = p("geoip2.subdivisions_2_names")
	require.True(t, ok)
	require.Equal(t, rec.Subdivisions[1].Names, v)
}

func TestGeoProviderDecodesAtMostOnce(t *testing.T) {
	a := geoProviderApp(t)
	decodes := countGeoDecodes(t)

	p := newGeoProvider(a, "wild", geoProviderReq("81.2.69.142:443", ""))

	// country_code and ip_address must NOT trigger the full decode.
	_, _ = p("geoip2.country_code")
	_, _ = p("geoip2.country_code")
	_, _ = p("geoip2.ip_address")
	require.Equal(t, 0, *decodes)

	// First exotic key triggers exactly one decode ...
	_, _ = p("geoip2.country_eu")
	require.Equal(t, 1, *decodes)

	// ... and every further fixed/dynamic key reuses it.
	for _, key := range []string{
		"geoip2.city_name", "geoip2.location_latitude", "geoip2.subdivisions",
		"geoip2.traits_isp", "geoip2.country_names_en",
		"geoip2.subdivisions_1_names_en", "geoip2.postal_code",
		"geoip2.registeredcountry_iso_code", "geoip2.country_eu",
	} {
		_, _ = p(key)
	}
	require.Equal(t, 1, *decodes)
}

func TestGeoProviderXFFQuirks(t *testing.T) {
	a := geoProviderApp(t)

	// wild: LEFTMOST XFF entry wins over RemoteAddr.
	p := newGeoProvider(a, "wild", geoProviderReq("89.160.20.128:443", "81.2.69.142, 10.0.0.1"))
	v, ok := p("geoip2.ip_address")
	require.True(t, ok)
	require.Equal(t, "81.2.69.142", v)
	v, ok = p("geoip2.country_code")
	require.True(t, ok)
	require.Equal(t, "GB", v)

	// Comma WITHOUT a space does not split: the whole header fails to parse
	// as an IP, so no lookup runs and fixed keys serve the "" init.
	decodes := countGeoDecodes(t)
	p = newGeoProvider(a, "wild", geoProviderReq("89.160.20.128:443", "81.2.69.142,10.0.0.1"))
	v, ok = p("geoip2.country_code")
	require.True(t, ok)
	require.Equal(t, "", v)
	v, ok = p("geoip2.country_eu")
	require.True(t, ok)
	require.Equal(t, "", v) // string state, not bool
	require.Equal(t, 0, *decodes)

	// Absent XFF: RemoteAddr host.
	p = newGeoProvider(a, "wild", geoProviderReq("89.160.20.128:443", ""))
	v, ok = p("geoip2.country_code")
	require.True(t, ok)
	require.Equal(t, "SE", v)
	v, ok = p("geoip2.ip_address")
	require.True(t, ok)
	require.Equal(t, "89.160.20.128", v)
}

func TestGeoProviderStrictMode(t *testing.T) {
	a := geoProviderApp(t)
	for _, mode := range []string{"strict", "STRICT"} { // fork lowercases mode
		p := newGeoProvider(a, mode, geoProviderReq("89.160.20.128:443", "81.2.69.142"))
		v, ok := p("geoip2.ip_address")
		require.True(t, ok)
		require.Equal(t, "89.160.20.128", v, "mode %q", mode)
		v, ok = p("geoip2.country_code")
		require.True(t, ok)
		require.Equal(t, "SE", v, "mode %q", mode)
	}
}

func TestGeoProviderTrustedProxiesMode(t *testing.T) {
	a := geoProviderApp(t)

	withTrusted := func(r *http.Request, trusted bool) *http.Request {
		ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey,
			map[string]any{caddyhttp.TrustedProxyVarKey: trusted})
		return r.WithContext(ctx)
	}

	// Trusted proxy: XFF (leftmost) is used.
	r := withTrusted(geoProviderReq("89.160.20.128:443", "81.2.69.142, 10.0.0.1"), true)
	p := newGeoProvider(a, "trusted_proxies", r)
	v, ok := p("geoip2.country_code")
	require.True(t, ok)
	require.Equal(t, "GB", v)

	// Untrusted: RemoteAddr despite XFF.
	r = withTrusted(geoProviderReq("89.160.20.128:443", "81.2.69.142"), false)
	p = newGeoProvider(a, "trusted_proxies", r)
	v, ok = p("geoip2.country_code")
	require.True(t, ok)
	require.Equal(t, "SE", v)

	// No vars map in context at all (fork would panic; we must not).
	p = newGeoProvider(a, "trusted_proxies", geoProviderReq("89.160.20.128:443", "81.2.69.142"))
	v, ok = p("geoip2.country_code")
	require.True(t, ok)
	require.Equal(t, "SE", v)
}

// RemoteAddr without a port takes the fork's missing-port fallback path.
func TestGeoProviderRemoteAddrWithoutPort(t *testing.T) {
	a := geoProviderApp(t)
	p := newGeoProvider(a, "strict", geoProviderReq("81.2.69.142", ""))
	v, ok := p("geoip2.country_code")
	require.True(t, ok)
	require.Equal(t, "GB", v)
}

// A nil app (gate without the apx app) must not panic: lookup "runs"
// (IP parsed) and serves typed zero values, like a DB-less lookup.
func TestGeoProviderNilApp(t *testing.T) {
	p := newGeoProvider(nil, "wild", geoProviderReq("81.2.69.142:443", ""))
	v, ok := p("geoip2.country_code")
	require.True(t, ok)
	require.Equal(t, "", v)
	v, ok = p("geoip2.country_eu")
	require.True(t, ok)
	require.Equal(t, false, v)
	v, ok = p("geoip2.ip_address")
	require.True(t, ok)
	require.Equal(t, "81.2.69.142", v)
}
