package apxchallenge

import (
	"strconv"
	"strings"
)

// renderPage is replaced by the embedded-asset version in Task 5. This stub
// returns a minimal page referencing the flow so handler tests can assert on it.
func renderPage(challengeToken string, difficulty int, verifyPath string) string {
	return strings.NewReplacer(
		"{{CHALLENGE}}", challengeToken,
		"{{DIFFICULTY}}", strconv.Itoa(difficulty),
		"{{VERIFY_PATH}}", verifyPath,
	).Replace(`<!doctype html><html><body data-cookie="apx-challenge">` +
		`<form id="apx-challenge" data-challenge="{{CHALLENGE}}" data-difficulty="{{DIFFICULTY}}" data-verify="{{VERIFY_PATH}}"></form>` +
		`</body></html>`)
}
