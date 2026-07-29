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

//go:embed assets/form_widget.js
var formWidgetJS string

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

// renderFormWidget substitutes the endpoint paths into the embedded widget.
// Served as application/javascript with a long cache + ETag by the handler.
func renderFormWidget(challengePath, tokenPath string) string {
	return strings.NewReplacer(
		"{{CHALLENGE_PATH}}", challengePath,
		"{{TOKEN_PATH}}", tokenPath,
	).Replace(formWidgetJS)
}
