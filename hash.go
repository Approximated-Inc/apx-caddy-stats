package apxstats

import (
	"hash/fnv"
)

// ClientHash returns a 64-bit FNV-1a hash of (ip || sep || ua || sep || salt).
//
// The salt is a per-deployment shared secret (env var `APX_HASH_SALT`) that
// makes the hash non-reversible to the original IP without the salt. A
// ClickHouse reader can't brute-force IPv4 (4 billion possibilities × short
// UA list = tractable) without the salt; with it, the search space includes
// the entire 256-bit salt entropy.
//
// Two clusters with different salts emit hashes that don't compare —
// preventing cross-cluster client correlation by anyone with read access
// to multiple clusters' data.
//
// FNV-1a is fine here. The hash isn't a cryptographic primitive — we just
// need uniform distribution + obfuscation. SHA-256 or similar would cost
// 100x more CPU on the hot path for negligible benefit at this threat model.
func ClientHash(ip, ua, salt string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(ip))
	h.Write([]byte{0x1f})
	h.Write([]byte(ua))
	h.Write([]byte{0x1f})
	h.Write([]byte(salt))
	return h.Sum64()
}
