package apxchallenge

// Probes is the JSON the widget posts to /__apx_verify/token. All fields are
// attacker-controlled — treat as untrusted signal, never as ground truth.
type Probes struct {
	FillMs       int64    `json:"fill_ms"`      // load → token-request elapsed
	Interactions int      `json:"interactions"` // input/pointer events seen
	Webdriver    bool     `json:"webdriver"`    // navigator.webdriver
	MissingAPIs  []string `json:"missing_apis"` // expected browser APIs found absent
}

// ScoreProbes applies the mode's ruleset. It errs toward passing: a false
// block silently breaks a real customer form, so only high-signal tells
// block in lenient mode. Returns (ok, reason); reason is "" when ok.
func ScoreProbes(p Probes, mode string, minFillMs int64) (bool, string) {
	if mode == "off" {
		return true, ""
	}
	if p.Webdriver {
		return false, "webdriver"
	}
	if p.FillMs > 0 && p.FillMs < minFillMs {
		return false, "too_fast"
	}
	if len(p.MissingAPIs) >= 3 {
		return false, "missing_apis"
	}
	if mode == "strict" && p.Interactions <= 0 {
		return false, "no_interaction"
	}
	return true, ""
}
