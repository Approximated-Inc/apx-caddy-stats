package apxchallenge

import (
	"crypto/sha256"
	"math/bits"
	"strconv"
)

// PoW hash input is the literal construction: seed + "." + solution.
// This MUST stay identical across the server verify path, the browser solver
// (pow.js), and SolvePoW below — any divergence makes solutions unverifiable.
const powSeparator = "."

// leadingZeroBits returns the number of leading zero bits in SHA-256(seed.solution).
func leadingZeroBits(seed, solution string) int {
	sum := sha256.Sum256([]byte(seed + powSeparator + solution))
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 8
			continue
		}
		n += bits.LeadingZeros8(b)
		break
	}
	return n
}

// VerifyPoW reports whether SHA-256(seed.solution) has >= difficulty leading
// zero bits. Cheap (one hash) — safe on the request hot path.
// NOTE: difficulty <= 0 DISABLES the PoW gate (verification always passes), so a
// config typo like `difficulty: 0` silently disables this deterrent — the HMAC
// cookie/token still gates separately in the handler.
func VerifyPoW(seed, solution string, difficulty int) bool {
	if difficulty <= 0 {
		return true
	}
	return leadingZeroBits(seed, solution) >= difficulty
}

// SolvePoW brute-forces a solution. Used by tests and mirrors what pow.js does
// in the browser. NOT called on the server hot path.
func SolvePoW(seed string, difficulty int) string {
	for i := 0; ; i++ {
		s := strconv.Itoa(i)
		if VerifyPoW(seed, s, difficulty) {
			return s
		}
	}
}
