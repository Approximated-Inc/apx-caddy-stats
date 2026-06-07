package apxchallenge

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenderPageInlinesAssetsAndValues(t *testing.T) {
	html := renderPage("TOKEN123", 17, "/__apx_challenge/verify")
	require.Contains(t, html, "TOKEN123")                // challenge token injected
	require.Contains(t, html, "17")                      // difficulty injected
	require.Contains(t, html, "/__apx_challenge/verify") // verify path injected
	require.Contains(t, html, "async function solve")    // pow.js inlined
	require.Contains(t, html, "<style>")                 // css inlined
	require.NotContains(t, html, "{{")                   // no unreplaced placeholders
	require.Contains(t, html, `method="POST"`)           // native form POST
	require.Contains(t, html, `action="/__apx_challenge/verify"`)
	require.Contains(t, html, `name="solution"`)
}
