package apxstats

const (
	// FingerprintMaxKeysDefault caps distinct (ja3, ja4, outcome) keys per
	// machine per minute (spec #17). FingerprintIpMaxKeysDefault caps
	// distinct (ja4, ip) keys. 0 in IngestConfig disables the track.
	FingerprintMaxKeysDefault   = 5000
	FingerprintIpMaxKeysDefault = 10000

	// FingerprintOutcomeAllowed is the only outcome this handler emits in
	// v1 (D1) — connections reaching this recorder were allowed; block
	// routes close blocked connections upstream. Mirrors L4IpOutcomeAllowed.
	FingerprintOutcomeAllowed = "allowed"
)

// fingerprintKey is the natural identity of an aggregated fingerprint
// traffic row. TsUnixMin is set at record time (like L4SniKey) so a key
// straddling a minute boundary lands in the right bucket.
type fingerprintKey struct {
	TsUnixMin uint32
	JA3       string
	JA4       string
	Outcome   string
}

// fingerprintIpKey is the natural identity of an aggregated
// (ja4, ip) join row.
type fingerprintIpKey struct {
	TsUnixMin uint32
	JA4       string
	IP        string
}

type fingerprintCounter struct{ ConnectionCount uint64 }
