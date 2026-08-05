package apxchallenge

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSolveThenVerify(t *testing.T) {
	const seed = "challenge-token-abc"
	for _, diff := range []int{1, 8, 12} {
		sol := SolvePoW(seed, diff)
		require.True(t, VerifyPoW(seed, sol, diff), "solved value must verify at difficulty %d", diff)
	}
}

func TestVerifyRejectsWrongSolution(t *testing.T) {
	require.False(t, VerifyPoW("seed", "not-a-solution", 12))
}

func TestVerifyRejectsLowerDifficulty(t *testing.T) {
	// Pinned (seed, solution) pair. leadingZeroBits("seed", "18") == 4 (in [4,15]).
	// Pinned rather than using SolvePoW("seed", 4): SolvePoW returns the FIRST
	// nonce, which is biased toward extra leading zeros, so its result occasionally
	// also clears 16 bits and the <16 assertion would flake (~1/10000). Hardcoding
	// the exact nonce makes this fully deterministic.
	const pinned = "18" // SHA-256("seed.18") has exactly 4 leading zero bits
	require.True(t, VerifyPoW("seed", pinned, 4), "pinned solution must clear difficulty 4")
	require.False(t, VerifyPoW("seed", pinned, 16), "pinned solution must NOT clear difficulty 16")
}

// TestLeadingZeroBitsByteBoundary locks the across-byte-boundary bit counting in
// leadingZeroBits (unexported, in-package). For a fixed seed it finds the FIRST
// solution at each target bit-count (first-match scan is deterministic) and
// asserts the function reports the EXACT count, not just a threshold. Covers a
// 0-bit case (top bit of first byte set), an 8-bit case (first byte zero, second
// non-zero), and a 12-bit case (crossing the first/second byte boundary).
func TestLeadingZeroBitsByteBoundary(t *testing.T) {
	const seed = "seed"
	cases := []struct {
		solution string
		want     int
	}{
		{"0", 0},      // first byte's top bit is set
		{"2", 1},      // single leading zero bit, still within first byte
		{"18", 4},     // mid-first-byte
		{"269", 8},    // first byte zero, second byte non-zero with top bit set
		{"16872", 12}, // crosses the first/second byte boundary
	}
	for _, c := range cases {
		got := leadingZeroBits(seed, c.solution)
		require.Equal(t, c.want, got, "leadingZeroBits(%q, %q)", seed, c.solution)
	}
}

func TestVerifyDifficultyZeroAlwaysPasses(t *testing.T) {
	require.True(t, VerifyPoW("seed", "anything", 0))
}
