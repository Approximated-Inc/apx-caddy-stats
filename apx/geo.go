// Geo reader for the apps.apx Caddy app.
//
// Lifecycle (LOCKED decision, mirrors the incumbent caddy-geoip2 module):
// the mmdb is mmap'd once at Provision and NEVER explicitly closed — not in
// Stop, not in Cleanup. During a config reload the old and new apps briefly
// overlap; an explicit Close on the old reader would race in-flight lookups
// (use-after-close on the mmap). The old mapping is released when the reader
// is garbage-collected or on process exit, exactly like today's
// geoip2_state.go behavior. A fresh Provision re-opens the (possibly
// cron-swapped) file, so mmdb freshness stays coupled to config loads.
//
// Concurrency: *maxminddb.Reader is safe for concurrent use — Lookup is
// read-only over the mmap — so GeoCountryCode/GeoRecord need no locking.
package apxapp

import (
	"net"

	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
)

// GeoConfig configures the geo reader on the apx app.
type GeoConfig struct {
	// DBPath is the path to a MaxMind City-schema mmdb (GeoLite2-City in
	// prod). Empty disables geo entirely: all lookups return zero values.
	DBPath string `json:"db_path,omitempty"`
}

// geoCountryRecord decodes ONLY country.iso_code — the measured fast path
// (~90% of geo CPU today is decoding the full City record just to read the
// country code).
type geoCountryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// GeoRecord is the full City-schema record, transcribed field-for-field
// (tags included, quirks included) from the incumbent fork's GeoIP2Record
// (Approximated-Inc/caddy-geoip2@f6406181 geoip2.go:18-106) so the Task 3
// placeholder surface decodes byte-identically. Note the Locales fields
// carry only json tags in the fork — the maxminddb decoder therefore never
// populates them (field name "Locales" != mmdb key "locales"); that dead
// behavior is preserved deliberately.
type GeoRecord struct {
	Country struct {
		Locales           []string          `json:"locales"`
		Confidence        uint16            `maxminddb:"confidence"`
		ISOCode           string            `maxminddb:"iso_code"`
		IsInEuropeanUnion bool              `maxminddb:"is_in_european_union"`
		Names             map[string]string `maxminddb:"names"`
		GeoNameID         uint64            `maxminddb:"geoname_id"`
	} `maxminddb:"country"`

	Continent struct {
		Locales   []string          `json:"locales"`
		Code      string            `maxminddb:"code"`
		GeoNameID uint              `maxminddb:"geoname_id"`
		Names     map[string]string `maxminddb:"names"`
	} `maxminddb:"continent"`

	City struct {
		Names      map[string]string `maxminddb:"names"`
		Confidence uint16            `maxminddb:"confidence"`
		GeoNameID  uint64            `maxminddb:"geoname_id"`
		Locales    []string          `json:"locales"`
	} `maxminddb:"city"`

	Location struct {
		AccuracyRadius    uint16  `maxminddb:"accuracy_radius"`
		AverageIncome     uint16  `maxminddb:"average_income"`
		Latitude          float64 `maxminddb:"latitude"`
		Longitude         float64 `maxminddb:"longitude"`
		MetroCode         uint    `maxminddb:"metro_code"`
		PopulationDensity uint    `maxminddb:"population_density"`
		TimeZone          string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`

	Postal struct {
		Code       string `maxminddb:"code"`
		Confidence uint16 `maxminddb:"confidence"`
	} `maxminddb:"postal"`

	RegisteredCountry struct {
		GeoNameID         uint              `maxminddb:"geoname_id"`
		IsInEuropeanUnion bool              `maxminddb:"is_in_european_union"`
		IsoCode           string            `maxminddb:"iso_code"`
		Names             map[string]string `maxminddb:"names"`
	} `maxminddb:"registered_country"`

	RepresentedCountry struct {
		Locales           []string          `json:"locales"`
		Confidence        uint16            `maxminddb:"confidence"`
		GeoNameID         uint              `maxminddb:"geoname_id"`
		IsInEuropeanUnion bool              `maxminddb:"is_in_european_union"`
		IsoCode           string            `maxminddb:"iso_code"`
		Names             map[string]string `maxminddb:"names"`
		Type              string            `maxminddb:"type"`
	} `maxminddb:"represented_country"`

	Subdivisions []struct {
		Locales    []string          `json:"locales"`
		Confidence uint16            `maxminddb:"confidence"`
		GeoNameID  uint              `maxminddb:"geoname_id"`
		IsoCode    string            `maxminddb:"iso_code"`
		Names      map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`

	Traits struct {
		IsAnonymousProxy    bool `maxminddb:"is_anonymous_proxy"`
		IsAnonymousVpn      bool `maxminddb:"is_anonymous_vpn"`
		IsSatelliteProvider bool `maxminddb:"is_satellite_provider"`

		AutonomousSystemNumber       uint64 `maxminddb:"autonomous_system_number"`
		AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
		ConnectionType               string `maxminddb:"connection_type"`
		Domain                       string `maxminddb:"domain"`

		IsHostingProvider  bool    `maxminddb:"is_hosting_provider"`
		IsLegitimateProxy  bool    `maxminddb:"is_legitimate_proxy"`
		IsPublicProxy      bool    `maxminddb:"is_public_proxy"`
		IsResidentialProxy bool    `maxminddb:"is_residential_proxy"`
		IsTorExitNode      bool    `maxminddb:"is_tor_exit_node"`
		Isp                string  `maxminddb:"isp"`
		MobileCountryCode  string  `maxminddb:"mobile_country_code"`
		MobileNetworkCode  string  `maxminddb:"mobile_network_code"`
		Network            string  `maxminddb:"network"`
		Organization       string  `maxminddb:"organization"`
		UserType           string  `maxminddb:"user_type"`
		UserCount          int32   `maxminddb:"userCount"`
		StaticIpScore      float64 `maxminddb:"static_ip_score"`
	} `maxminddb:"traits"`
}

// provisionGeo opens the mmdb configured in a.Geo. A missing or corrupt file
// logs ONE warning and leaves the reader nil — a bad geo DB must never take
// down the proxy (facts §implication 7); all lookups then return zero values.
func (a *App) provisionGeo() {
	if a.Geo.DBPath == "" {
		return
	}
	rdr, err := maxminddb.Open(a.Geo.DBPath)
	if err != nil {
		a.logger.Warn("apx: geo database unavailable, geo lookups disabled",
			zap.String("db_path", a.Geo.DBPath), zap.Error(err))
		return
	}
	a.geo = rdr
}

// GeoCountryCode returns the ISO country code for ip, decoding only
// country.iso_code (fast path). Returns "" when the reader is nil, ip is
// nil, the IP is not in the database, or on any lookup error.
func (a *App) GeoCountryCode(ip net.IP) string {
	if a.geo == nil || ip == nil {
		return ""
	}
	var rec geoCountryRecord
	if err := a.geo.Lookup(ip, &rec); err != nil {
		return ""
	}
	return rec.Country.ISOCode
}

// GeoRecord returns the full City-schema record for ip. ok is false when no
// lookup could be performed (nil reader, nil ip, or lookup error). A lookup
// MISS (IP not in the database) returns a zero-valued record with ok=true,
// matching the fork, which sets its placeholders from the zero record on
// miss. Nothing is cached; callers cache per request.
func (a *App) GeoRecord(ip net.IP) (*GeoRecord, bool) {
	if a.geo == nil || ip == nil {
		return nil, false
	}
	var rec GeoRecord
	if err := a.geo.Lookup(ip, &rec); err != nil {
		return nil, false
	}
	return &rec, true
}
