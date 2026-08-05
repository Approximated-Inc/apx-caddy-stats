// Lazy geoip2.* replacer provider for the apx_gate handler.
//
// Reproduces the observable placeholder surface of the incumbent fork
// Approximated-Inc/caddy-geoip2@f6406181 (geoip2.go ServeHTTP) WITHOUT doing
// the eager ~100 repl.Set calls + full record decode on every request. The
// fork's behavior has two observable states, both preserved here:
//
//  1. NO LOOKUP RAN (mode off, or no client IP parseable): every FIXED key
//     (the fork's blanket empty-string init, geoip2.go:143-238) resolves as
//     ("", true). Keys outside the fixed list — including dynamic-family
//     keys — were never Set, so they resolve (nil, false).
//  2. LOOKUP RAN (mode enables lookup and a client IP parsed — INCLUDING
//     lookup errors and in-DB misses, which the fork ignores): every fixed
//     key resolves with the TYPED value from the (possibly zero) record —
//     bools as false, numerics as 0, strings "", maps/slices as decoded —
//     via the exact field expressions of the fork's repl.Set calls. So e.g.
//     geoip2.country_eu is false (bool) after a miss but "" (string) when no
//     lookup happened. Dynamic keys (…_names_<locale>, subdivisions_<n>_…)
//     resolve per the fork's loops; underivable ones are (nil, false).
//
// Laziness: geoip2.country_code is served from the App's country-only fast
// path; geoip2.ip_address needs no decode at all. Any OTHER fixed or dynamic
// key triggers the one-time full GeoRecord decode, memoized per request.
//
// The returned closure is NOT safe for concurrent use — Caddy replacer
// providers run on the request goroutine, matching the replacer itself.
package apxstats

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	apxapp "github.com/Approximated-Inc/apx-caddy-stats/apx"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const geoip2Prefix = "geoip2."

// geoDecodeTestHook, when non-nil, is invoked each time a provider performs
// its one-time full GeoRecord decode. Test-only instrumentation.
var geoDecodeTestHook func()

// geoFixedKeys is the fork's CLOSED list of blanket-initialized placeholder
// keys, transcribed verbatim from phase2-facts.md §3a (= the fork's init
// block, geoip2.go:143-238). Keys not in this list and not dynamic-derivable
// resolve (nil, false) in both states.
var geoFixedKeys = func() map[string]struct{} {
	keys := []string{
		"geoip2.ip_address",
		"geoip2.country_code", "geoip2.country_name", "geoip2.country_eu", "geoip2.country_locales", "geoip2.country_confidence", "geoip2.country_names", "geoip2.country_names_0", "geoip2.country_names_1", "geoip2.country_geoname_id",
		"geoip2.continent_code", "geoip2.continent_locales", "geoip2.continent_names", "geoip2.continent_names_0", "geoip2.continent_names_1", "geoip2.continent_geoname_id", "geoip2.continent_name",
		"geoip2.city_confidence", "geoip2.city_locales", "geoip2.city_names", "geoip2.city_names_0", "geoip2.city_names_1", "geoip2.city_geoname_id", "geoip2.city_name",
		"geoip2.location_latitude", "geoip2.location_longitude", "geoip2.location_time_zone", "geoip2.location_accuracy_radius", "geoip2.location_average_income", "geoip2.location_metro_code", "geoip2.location_population_density",
		"geoip2.postal_code", "geoip2.postal_confidence",
		"geoip2.registeredcountry_geoname_id", "geoip2.registeredcountry_is_in_european_union", "geoip2.registeredcountry_iso_code", "geoip2.registeredcountry_names", "geoip2.registeredcountry_names_0", "geoip2.registeredcountry_names_1", "geoip2.registeredcountry_name",
		"geoip2.representedcountry_geoname_id", "geoip2.representedcountry_is_in_european_union", "geoip2.representedcountry_iso_code", "geoip2.representedcountry_names", "geoip2.representedcountry_locales", "geoip2.representedcountry_confidence", "geoip2.representedcountry_type", "geoip2.representedcountry_name", "geoip2.representedcountry_names_0", "geoip2.representedcountry_names_1",
		"geoip2.subdivisions",
		"geoip2.traits_is_anonymous_proxy", "geoip2.traits_is_anonymous_vpn", "geoip2.traits_is_satellite_provider", "geoip2.traits_autonomous_system_number", "geoip2.traits_autonomous_system_organization", "geoip2.traits_connection_type", "geoip2.traits_domain", "geoip2.traits_is_hosting_provider", "geoip2.traits_is_legitimate_proxy", "geoip2.traits_is_public_proxy", "geoip2.traits_is_residential_proxy", "geoip2.traits_is_tor_exit_node", "geoip2.traits_isp", "geoip2.traits_mobile_country_code", "geoip2.traits_mobile_network_code", "geoip2.traits_network", "geoip2.traits_organization", "geoip2.traits_user_type", "geoip2.traits_userCount", "geoip2.traits_static_ip_score",
		"geoip2.subdivisions_1_confidence", "geoip2.subdivisions_1_geoname_id", "geoip2.subdivisions_1_iso_code", "geoip2.subdivisions_1_locales", "geoip2.subdivisions_1_locales_en", "geoip2.subdivisions_1_names", "geoip2.subdivisions_1_names_0", "geoip2.subdivisions_1_names_1", "geoip2.subdivisions_1_name",
		"geoip2.subdivisions_2_confidence", "geoip2.subdivisions_2_geoname_id", "geoip2.subdivisions_2_iso_code", "geoip2.subdivisions_2_locales", "geoip2.subdivisions_2_locales_en", "geoip2.subdivisions_2_names", "geoip2.subdivisions_2_names_0", "geoip2.subdivisions_2_names_1", "geoip2.subdivisions_2_name",
	}
	m := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		m[k] = struct{}{}
	}
	return m
}()

// newGeoProvider returns a Caddy replacer Map provider serving the geoip2.*
// placeholder surface for one request. Construction is cheap (a closure over
// a few words); the client IP, the country fast path, and the full record
// decode are each computed at most once, on first demand.
func newGeoProvider(app *apxapp.App, mode string, r *http.Request) func(key string) (any, bool) {
	var (
		ipResolved bool
		ip         net.IP // nil after resolution => no lookup ran
		ccResolved bool
		cc         string
		rec        *apxapp.GeoRecord
	)
	resolveIP := func() net.IP {
		if !ipResolved {
			ipResolved = true
			if geoLookupEnabled(mode) {
				ip = geoClientIP(mode, r)
			}
		}
		return ip
	}
	fullRecord := func() *apxapp.GeoRecord {
		if rec == nil {
			if geoDecodeTestHook != nil {
				geoDecodeTestHook()
			}
			if app != nil {
				if got, ok := app.GeoRecord(ip); ok {
					rec = got
				}
			}
			if rec == nil {
				// No DB / lookup error: the fork ignores the error and
				// serves typed values from the zero record.
				rec = new(apxapp.GeoRecord)
			}
		}
		return rec
	}
	return func(key string) (any, bool) {
		if !strings.HasPrefix(key, geoip2Prefix) {
			return nil, false
		}
		clientIP := resolveIP()
		if clientIP == nil {
			// State 1: no lookup ran — the blanket "" init is all there is.
			if _, fixed := geoFixedKeys[key]; fixed {
				return "", true
			}
			return nil, false
		}
		// State 2: lookup ran.
		switch key {
		case "geoip2.ip_address":
			return clientIP.String(), true
		case "geoip2.country_code":
			if !ccResolved {
				ccResolved = true
				if app != nil {
					cc = app.GeoCountryCode(clientIP)
				}
			}
			return cc, true
		}
		if _, fixed := geoFixedKeys[key]; fixed {
			return geoFixedValue(key, fullRecord()), true
		}
		return geoDynamicValue(key, fullRecord())
	}
}

// geoLookupEnabled mirrors the fork's off check (geoip2.go:240) verbatim:
// case-sensitive, and note "" is NOT off — it means default trusted_proxies
// mode (lookup still runs, from RemoteAddr when the proxy isn't trusted).
func geoLookupEnabled(mode string) bool {
	return mode != "off" && mode != "false" && mode != "0"
}

type geoIPSafeLevel int

const (
	geoWild geoIPSafeLevel = iota
	geoTrustedProxies
	geoStrict
)

// geoClientIP mirrors the fork's getClientIP (geoip2.go:395-434):
// "wild" (or "trusted_proxies" with the trusted-proxy var true) takes the
// LEFTMOST X-Forwarded-For entry when the header is present, splitting on
// ", " — a comma WITHOUT a space does not split, so such values fail
// net.ParseIP and no lookup runs. Otherwise the RemoteAddr host is used.
// Returns nil when no IP parses.
func geoClientIP(mode string, r *http.Request) net.IP {
	safeLevel := geoTrustedProxies
	switch strings.ToLower(mode) {
	case "strict":
		safeLevel = geoStrict
	case "wild":
		safeLevel = geoWild
	}

	trustedProxy, _ := caddyhttp.GetVar(r.Context(), caddyhttp.TrustedProxyVarKey).(bool)
	fwdFor := r.Header.Get("X-Forwarded-For")

	var ip string
	if ((safeLevel == geoTrustedProxies && trustedProxy) || safeLevel == geoWild) && fwdFor != "" {
		ip = strings.Split(fwdFor, ", ")[0]
	} else {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			var aerr *net.AddrError
			if errors.As(err, &aerr) && aerr.Err == "missing port in address" {
				ip = r.RemoteAddr
			} else {
				return nil
			}
		} else {
			ip = host
		}
	}
	return net.ParseIP(ip)
}

// geoNameOrEmpty serves the fork's loop-overwritten name keys: the blanket
// init sets "", and the names loop overwrites only when the locale key
// exists in the map. Both outcomes are (value, true).
func geoNameOrEmpty(names map[string]string, locale string) any {
	if v, ok := names[locale]; ok {
		return v
	}
	return ""
}

// geoFixedValue maps a fixed key (already membership-checked; ip_address and
// country_code are intercepted earlier) to the exact typed expression the
// fork passes to repl.Set after a lookup (geoip2.go:254-386).
func geoFixedValue(key string, rec *apxapp.GeoRecord) any {
	switch key {
	// country (fork geoip2.go:254-267)
	case "geoip2.country_name":
		return geoNameOrEmpty(rec.Country.Names, "en")
	case "geoip2.country_eu":
		return rec.Country.IsInEuropeanUnion
	case "geoip2.country_locales":
		return rec.Country.Locales
	case "geoip2.country_confidence":
		return rec.Country.Confidence
	case "geoip2.country_names":
		return rec.Country.Names
	case "geoip2.country_names_0":
		return geoNameOrEmpty(rec.Country.Names, "0")
	case "geoip2.country_names_1":
		return geoNameOrEmpty(rec.Country.Names, "1")
	case "geoip2.country_geoname_id":
		return rec.Country.GeoNameID

	// continent (fork geoip2.go:270-280)
	case "geoip2.continent_code":
		return rec.Continent.Code
	case "geoip2.continent_locales":
		return rec.Continent.Locales
	case "geoip2.continent_names":
		return rec.Continent.Names
	case "geoip2.continent_names_0":
		return geoNameOrEmpty(rec.Continent.Names, "0")
	case "geoip2.continent_names_1":
		return geoNameOrEmpty(rec.Continent.Names, "1")
	case "geoip2.continent_geoname_id":
		return rec.Continent.GeoNameID
	case "geoip2.continent_name":
		return geoNameOrEmpty(rec.Continent.Names, "en")

	// city (fork geoip2.go:283-295)
	case "geoip2.city_confidence":
		return rec.City.Confidence
	case "geoip2.city_locales":
		return rec.City.Locales
	case "geoip2.city_names":
		return rec.City.Names
	case "geoip2.city_names_0":
		return geoNameOrEmpty(rec.City.Names, "0")
	case "geoip2.city_names_1":
		return geoNameOrEmpty(rec.City.Names, "1")
	case "geoip2.city_geoname_id":
		return rec.City.GeoNameID
	case "geoip2.city_name":
		return geoNameOrEmpty(rec.City.Names, "en")

	// location (fork geoip2.go:298-304)
	case "geoip2.location_latitude":
		return rec.Location.Latitude
	case "geoip2.location_longitude":
		return rec.Location.Longitude
	case "geoip2.location_time_zone":
		return rec.Location.TimeZone
	case "geoip2.location_accuracy_radius":
		return rec.Location.AccuracyRadius
	case "geoip2.location_average_income":
		return rec.Location.AverageIncome
	case "geoip2.location_metro_code":
		return rec.Location.MetroCode
	case "geoip2.location_population_density":
		return rec.Location.PopulationDensity

	// postal (fork geoip2.go:307-308)
	case "geoip2.postal_code":
		return rec.Postal.Code
	case "geoip2.postal_confidence":
		return rec.Postal.Confidence

	// registered country (fork geoip2.go:311-323)
	case "geoip2.registeredcountry_geoname_id":
		return rec.RegisteredCountry.GeoNameID
	case "geoip2.registeredcountry_is_in_european_union":
		return rec.RegisteredCountry.IsInEuropeanUnion
	case "geoip2.registeredcountry_iso_code":
		return rec.RegisteredCountry.IsoCode
	case "geoip2.registeredcountry_names":
		return rec.RegisteredCountry.Names
	case "geoip2.registeredcountry_names_0":
		return geoNameOrEmpty(rec.RegisteredCountry.Names, "0")
	case "geoip2.registeredcountry_names_1":
		return geoNameOrEmpty(rec.RegisteredCountry.Names, "1")
	case "geoip2.registeredcountry_name":
		return geoNameOrEmpty(rec.RegisteredCountry.Names, "en")

	// represented country (fork geoip2.go:326-341)
	case "geoip2.representedcountry_geoname_id":
		return rec.RepresentedCountry.GeoNameID
	case "geoip2.representedcountry_is_in_european_union":
		return rec.RepresentedCountry.IsInEuropeanUnion
	case "geoip2.representedcountry_iso_code":
		return rec.RepresentedCountry.IsoCode
	case "geoip2.representedcountry_names":
		return rec.RepresentedCountry.Names
	case "geoip2.representedcountry_locales":
		return rec.RepresentedCountry.Locales
	case "geoip2.representedcountry_confidence":
		return rec.RepresentedCountry.Confidence
	case "geoip2.representedcountry_type":
		return rec.RepresentedCountry.Type
	case "geoip2.representedcountry_name":
		return geoNameOrEmpty(rec.RepresentedCountry.Names, "en")
	case "geoip2.representedcountry_names_0":
		return geoNameOrEmpty(rec.RepresentedCountry.Names, "0")
	case "geoip2.representedcountry_names_1":
		return geoNameOrEmpty(rec.RepresentedCountry.Names, "1")

	// subdivisions slice (fork geoip2.go:343)
	case "geoip2.subdivisions":
		return rec.Subdivisions

	// traits (fork geoip2.go:365-386)
	case "geoip2.traits_is_anonymous_proxy":
		return rec.Traits.IsAnonymousProxy
	case "geoip2.traits_is_anonymous_vpn":
		return rec.Traits.IsAnonymousVpn
	case "geoip2.traits_is_satellite_provider":
		return rec.Traits.IsSatelliteProvider
	case "geoip2.traits_autonomous_system_number":
		return rec.Traits.AutonomousSystemNumber
	case "geoip2.traits_autonomous_system_organization":
		return rec.Traits.AutonomousSystemOrganization
	case "geoip2.traits_connection_type":
		return rec.Traits.ConnectionType
	case "geoip2.traits_domain":
		return rec.Traits.Domain
	case "geoip2.traits_is_hosting_provider":
		return rec.Traits.IsHostingProvider
	case "geoip2.traits_is_legitimate_proxy":
		return rec.Traits.IsLegitimateProxy
	case "geoip2.traits_is_public_proxy":
		return rec.Traits.IsPublicProxy
	case "geoip2.traits_is_residential_proxy":
		return rec.Traits.IsResidentialProxy
	case "geoip2.traits_is_tor_exit_node":
		return rec.Traits.IsTorExitNode
	case "geoip2.traits_isp":
		return rec.Traits.Isp
	case "geoip2.traits_mobile_country_code":
		return rec.Traits.MobileCountryCode
	case "geoip2.traits_mobile_network_code":
		return rec.Traits.MobileNetworkCode
	case "geoip2.traits_network":
		return rec.Traits.Network
	case "geoip2.traits_organization":
		return rec.Traits.Organization
	case "geoip2.traits_user_type":
		return rec.Traits.UserType
	case "geoip2.traits_userCount":
		return rec.Traits.UserCount
	case "geoip2.traits_static_ip_score":
		return rec.Traits.StaticIpScore

	// pre-declared subdivisions_1_* / subdivisions_2_* (fork geoip2.go:220-238
	// init; overwritten by the loop at 345-362 only when the subdivision exists)
	case "geoip2.subdivisions_1_confidence":
		return geoSubdivisionFixed(rec, 1, "confidence")
	case "geoip2.subdivisions_1_geoname_id":
		return geoSubdivisionFixed(rec, 1, "geoname_id")
	case "geoip2.subdivisions_1_iso_code":
		return geoSubdivisionFixed(rec, 1, "iso_code")
	case "geoip2.subdivisions_1_locales":
		return geoSubdivisionFixed(rec, 1, "locales")
	case "geoip2.subdivisions_1_locales_en":
		return geoSubdivisionFixed(rec, 1, "locales_en")
	case "geoip2.subdivisions_1_names":
		return geoSubdivisionFixed(rec, 1, "names")
	case "geoip2.subdivisions_1_names_0":
		return geoSubdivisionFixed(rec, 1, "names_0")
	case "geoip2.subdivisions_1_names_1":
		return geoSubdivisionFixed(rec, 1, "names_1")
	case "geoip2.subdivisions_1_name":
		return geoSubdivisionFixed(rec, 1, "name")
	case "geoip2.subdivisions_2_confidence":
		return geoSubdivisionFixed(rec, 2, "confidence")
	case "geoip2.subdivisions_2_geoname_id":
		return geoSubdivisionFixed(rec, 2, "geoname_id")
	case "geoip2.subdivisions_2_iso_code":
		return geoSubdivisionFixed(rec, 2, "iso_code")
	case "geoip2.subdivisions_2_locales":
		return geoSubdivisionFixed(rec, 2, "locales")
	case "geoip2.subdivisions_2_locales_en":
		return geoSubdivisionFixed(rec, 2, "locales_en")
	case "geoip2.subdivisions_2_names":
		return geoSubdivisionFixed(rec, 2, "names")
	case "geoip2.subdivisions_2_names_0":
		return geoSubdivisionFixed(rec, 2, "names_0")
	case "geoip2.subdivisions_2_names_1":
		return geoSubdivisionFixed(rec, 2, "names_1")
	case "geoip2.subdivisions_2_name":
		return geoSubdivisionFixed(rec, 2, "name")
	}
	// Unreachable for membership-checked keys; keep the blanket-init value.
	return ""
}

// geoSubdivisionFixed serves the pre-declared subdivisions_1_*/_2_* keys.
// When the record has fewer than n subdivisions the fork's loop never runs,
// so the blanket "" init survives — even after a lookup.
func geoSubdivisionFixed(rec *apxapp.GeoRecord, n int, field string) any {
	if len(rec.Subdivisions) < n {
		return ""
	}
	sub := rec.Subdivisions[n-1]
	switch field {
	case "confidence":
		return sub.Confidence
	case "geoname_id":
		return sub.GeoNameID
	case "iso_code":
		return sub.IsoCode
	case "locales":
		return sub.Locales
	case "locales_en":
		// The fork's locales loop writes integer-indexed keys only
		// (locales_0, locales_1, …); "locales_en" is never overwritten.
		return ""
	case "names":
		return sub.Names
	case "names_0":
		return geoNameOrEmpty(sub.Names, "0")
	case "names_1":
		return geoNameOrEmpty(sub.Names, "1")
	case "name":
		return geoNameOrEmpty(sub.Names, "en")
	}
	return ""
}

// geoDynamicValue resolves keys outside the fixed list that the fork's
// post-lookup loops COULD have Set: locale-suffixed name keys and
// subdivisions_<n>_* keys. Anything the loops would not have written
// resolves (nil, false), exactly like an unset replacer key today.
func geoDynamicValue(key string, rec *apxapp.GeoRecord) (any, bool) {
	suffix := strings.TrimPrefix(key, geoip2Prefix)

	if loc, ok := strings.CutPrefix(suffix, "country_names_"); ok {
		return geoLocaleName(rec.Country.Names, loc)
	}
	if loc, ok := strings.CutPrefix(suffix, "continent_names_"); ok {
		return geoLocaleName(rec.Continent.Names, loc)
	}
	if loc, ok := strings.CutPrefix(suffix, "city_names_"); ok {
		return geoLocaleName(rec.City.Names, loc)
	}
	if loc, ok := strings.CutPrefix(suffix, "registeredcountry_names_"); ok {
		return geoLocaleName(rec.RegisteredCountry.Names, loc)
	}
	if loc, ok := strings.CutPrefix(suffix, "representedcountry_names_"); ok {
		return geoLocaleName(rec.RepresentedCountry.Names, loc)
	}
	if rest, ok := strings.CutPrefix(suffix, "subdivisions_"); ok {
		return geoSubdivisionDynamic(rec, rest)
	}
	return nil, false
}

func geoLocaleName(names map[string]string, locale string) (any, bool) {
	if v, ok := names[locale]; ok {
		return v, true
	}
	return nil, false
}

// geoSubdivisionDynamic resolves subdivisions_<n>_<field> keys per the
// fork's loop (geoip2.go:345-362). rest is everything after "subdivisions_".
// The index must be the canonical decimal the fork's strconv.Itoa produced.
func geoSubdivisionDynamic(rec *apxapp.GeoRecord, rest string) (any, bool) {
	i := strings.IndexByte(rest, '_')
	if i <= 0 {
		return nil, false
	}
	n, err := strconv.Atoi(rest[:i])
	if err != nil || rest[:i] != strconv.Itoa(n) || n < 1 || n > len(rec.Subdivisions) {
		return nil, false
	}
	sub := rec.Subdivisions[n-1]
	field := rest[i+1:]
	switch field {
	case "confidence":
		return sub.Confidence, true
	case "geoname_id":
		return sub.GeoNameID, true
	case "iso_code":
		return sub.IsoCode, true
	case "locales":
		return sub.Locales, true
	case "names":
		return sub.Names, true
	case "name":
		// Set only when an "en" name exists (no blanket init for n >= 3).
		if v, ok := sub.Names["en"]; ok {
			return v, true
		}
		return nil, false
	}
	if loc, ok := strings.CutPrefix(field, "names_"); ok {
		if v, ok := sub.Names[loc]; ok {
			return v, true
		}
		return nil, false
	}
	if idxStr, ok := strings.CutPrefix(field, "locales_"); ok {
		idx, err := strconv.Atoi(idxStr)
		if err == nil && idxStr == strconv.Itoa(idx) && idx >= 0 && idx < len(sub.Locales) {
			return sub.Locales[idx], true
		}
		return nil, false
	}
	return nil, false
}
