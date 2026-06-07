package apxchallenge

import (
	_ "embed"
	"strconv"
	"strings"
)

//go:embed assets/challenge.html
var pageHTML string

//go:embed assets/pow.js
var powJS string

//go:embed assets/challenge.css
var pageCSS string

// renderPage inlines the CSS + JS and injects the per-request challenge token,
// difficulty, and verify path. One self-contained HTML response — no separate
// asset routes to wire.
func renderPage(challengeToken string, difficulty int, verifyPath string) string {
	return strings.NewReplacer(
		"{{CSS}}", pageCSS,
		"{{JS}}", powJS,
		"{{CHALLENGE}}", challengeToken,
		"{{DIFFICULTY}}", strconv.Itoa(difficulty),
		"{{VERIFY_PATH}}", verifyPath,
	).Replace(pageHTML)
}
