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
	sol := SolvePoW("seed", 4)
	require.False(t, VerifyPoW("seed", sol, 16))
}

func TestVerifyDifficultyZeroAlwaysPasses(t *testing.T) {
	require.True(t, VerifyPoW("seed", "anything", 0))
}
