package apxstats

import (
	"hash/fnv"
	"net/netip"
	"strconv"
	"strings"
)

// Phase 2 per-IP tracking constants. All values are LOCKED by the
// Phase 2 spec (Open Q 2.4 / 2.5 / sampling math) and exposed here as
// package constants — no IngestConfig knobs.
const (
	// topkSize is the K parameter for the per-machine, per-flush
	// top-K heavy-hitter sketch over client IPs. K=1000 is enough
	// to capture the heavy tail under attack at our per-machine
	// connection rates without ballooning the sketch's CMS counters.
	topkSize = 1000

	// sampleDenom is the inverse sampling rate for the
	// `l4_ip_uniques_raw` track. The Caddy-side handler keeps
	// `1/sampleDenom` of distinct IPs and ships them as raw rows;
	// Phoenix synthesizes an HLL approximation by scaling cardinality
	// back up by sampleDenom. See HLL sampling-rate math doc in
	// Phoenix repo.
	sampleDenom = 16

	// ipSniMapCap bounds the (IP, SNI, outcome) breakdown map per
	// flush window. topkSize × maxSnisPerIp = the worst-case fan-out
	// before the per-IP SNI overflow sentinel kicks in.
	ipSniMapCap = topkSize * maxSnisPerIp

	// ipPrefixMapCap bounds the prefix-counter map per flush. Hitting
	// the cap drops new prefix keys silently (telemetry log only) —
	// no overflow sentinel; the TopK row signal still surfaces
	// abusive prefixes.
	ipPrefixMapCap = 100_000

	// v4PrefixLen / v6PrefixLen are the network prefix lengths used
	// to bucket connections in the prefix-counter map. /24 for IPv4
	// (mapped or native), /56 for native IPv6. Per spec lock — do not
	// switch to /48.
	v4PrefixLen = 24
	v6PrefixLen = 56

	// maxSnisPerIp caps the number of distinct SNIs tracked for a
	// single IP before further SNIs collapse into the per-IP
	// `__overflow__` sentinel (outcome preserved). 32 mirrors the
	// scanner-vs-legitimate-client ceiling we expect.
	maxSnisPerIp = 32

	// L4IpOverflowSNI is the synthetic SNI emitted for an IP when
	// it has already accumulated `maxSnisPerIp` distinct SNIs in the
	// current flush window. Same shape as the Phase 1 L4SniOverflowSNI
	// but scoped per-IP rather than per-machine.
	L4IpOverflowSNI = "__overflow__"

	// L4IpOutcomeAllowed is the only outcome the Caddy plugin emits
	// pre-Phase-9. Blocked connections never reach this handler —
	// the layer4 SNI/IP block routes close them upstream so the SNI
	// counter handler never sees them. Phase 9 (challenge module) will
	// introduce `"challenged"`; `"blocked"` stays Phoenix-side.
	L4IpOutcomeAllowed = "allowed"
)

// l4IpSniKey is the natural identity of an aggregated (IP, SNI, outcome)
// counter row. TsUnixMin is global per flush window so it's not part of
// the key — the flush stamps every row with the same minute.
type l4IpSniKey struct {
	IP      string
	SNI     string
	Outcome string
}

// l4IpPrefixKey identifies a per-(prefix, prefix-length) counter row.
// Prefix is the network address (host bits zeroed); PrefixLen is 24 or
// 56 depending on whether the source IP was v4-mapped or native v6.
type l4IpPrefixKey struct {
	Prefix    string
	PrefixLen uint8
}

// canonicalIPAndPrefix parses an IP string (with or without :port
// suffix), returns the canonical IP form, plus its prefix-network
// representation and prefix length per the Phase 2 spec lock.
//
// v4 + v4-in-v6 → /24 over the IPv4 portion (rendered as IPv4 dotted-
// quad with host bits zeroed).
// v6 native → /56.
//
// Returns ok=false for unparseable inputs; callers should drop those
// silently (they're a misconfigured upstream, not a workload signal).
func canonicalIPAndPrefix(ipStr string) (ip string, prefix string, prefixLen uint8, ok bool) {
	// Strip optional :port — cx.RemoteAddr().String() returns
	// "host:port"; netip.ParseAddr won't accept that.
	if i := strings.LastIndexByte(ipStr, ']'); i >= 0 {
		// "[v6]:port" form
		if i+1 < len(ipStr) && ipStr[i+1] == ':' {
			ipStr = ipStr[1:i]
		}
	} else if i := strings.LastIndexByte(ipStr, ':'); i >= 0 {
		// "v4:port" — but a bare "::1" or "fe80::1" has multiple ':'.
		// Distinguish by counting: a v4 has exactly one ':', a v6 has 2+.
		if strings.Count(ipStr, ":") == 1 {
			ipStr = ipStr[:i]
		}
	}

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return "", "", 0, false
	}

	// Unmap v4-in-v6 to the bare v4 form. ClickHouse's IPv6 column
	// stores both, but our prefix logic + canonical key dedup depends
	// on a single canonical representation per logical IP.
	addr = addr.Unmap()

	if addr.Is4() {
		pfx, err := addr.Prefix(v4PrefixLen)
		if err != nil {
			return "", "", 0, false
		}
		return addr.String(), pfx.Addr().String(), v4PrefixLen, true
	}

	// IPv6 native.
	pfx, err := addr.Prefix(v6PrefixLen)
	if err != nil {
		return "", "", 0, false
	}
	return addr.String(), pfx.Addr().String(), v6PrefixLen, true
}

// sampleIP returns true if the given canonical IP string should be
// included in the sampled-uniques set. Uses FNV-1a/64 modulo
// sampleDenom — deterministic per-IP so the same IP across flush
// windows lands the same way (preventing accidental double-counting
// when the same scanner appears in adjacent minutes).
func sampleIP(ip string) bool {
	h := fnv.New64a()
	h.Write([]byte(ip))
	return h.Sum64()%sampleDenom == 0
}

// l4IpSniKeyString builds the composite key used to dedup (IP, SNI,
// outcome) tuples in the breakdown map. The map could use a struct
// key directly; we use a string key for cache-friendly iteration in
// the flush path + faster JSON encode (no struct-field access in
// hot inner loop).
func l4IpSniKeyString(ip, sni, outcome string) string {
	var b strings.Builder
	b.Grow(len(ip) + len(sni) + len(outcome) + 2)
	b.WriteString(ip)
	b.WriteByte('|')
	b.WriteString(sni)
	b.WriteByte('|')
	b.WriteString(outcome)
	return b.String()
}

// l4IpPrefixKeyString mirrors l4IpSniKeyString for the prefix map.
func l4IpPrefixKeyString(prefix string, prefixLen uint8) string {
	var b strings.Builder
	b.Grow(len(prefix) + 4)
	b.WriteString(prefix)
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(prefixLen), 10))
	return b.String()
}
