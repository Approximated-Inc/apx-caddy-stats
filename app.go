package apxchallenge

import (
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&ChallengeApp{})
}

const (
	defaultDifficulty = 16
	defaultVerifyPath = "/__apx_challenge/verify"
)

// AppRef is what the handler depends on; tests inject a fake.
type AppRef interface {
	Secret() string
	Difficulty() int
	VerifyPath() string
	FormDifficulty() int
	FormTokenTTL() time.Duration
	FormMinFillMs() int64
	FormScoring() string
	FormBodyCap() int64
	// ReplayLRU is the process-wide, app-owned set of recently-seen form-token
	// nonces. Shared across all form routes so a token is single-use per machine.
	ReplayLRU() *NonceLRU
}

// ChallengeApp is the top-level Caddy app holding the per-cluster challenge
// secret (read inline from config), the PoW difficulty, and the verify endpoint
// path. Config keys mirror what Phoenix emits in apps.apx_challenge.
type ChallengeApp struct {
	// DifficultyCfg / SecretCfg / VerifyPathCfg carry the JSON config keys
	// difficulty / secret / verify_path. They use the *Cfg suffix because Go
	// forbids a struct field and a method sharing a name, and
	// Secret()/Difficulty()/VerifyPath() are the AppRef accessors handlers
	// depend on.
	DifficultyCfg int    `json:"difficulty,omitempty"`
	SecretCfg     string `json:"secret,omitempty"`
	VerifyPathCfg string `json:"verify_path,omitempty"`

	// FormDifficultyCfg / FormTokenTTLSecondsCfg / FormMinFillMsCfg /
	// FormScoringCfg / FormBodyCapBytesCfg carry the form-protection config
	// keys form_difficulty / form_token_ttl_seconds / form_min_fill_ms /
	// form_scoring / form_body_cap_bytes. Same *Cfg-suffix convention as above.
	FormDifficultyCfg      int    `json:"form_difficulty,omitempty"`
	FormTokenTTLSecondsCfg int    `json:"form_token_ttl_seconds,omitempty"`
	FormMinFillMsCfg       int64  `json:"form_min_fill_ms,omitempty"`
	FormScoringCfg         string `json:"form_scoring,omitempty"`
	FormBodyCapBytesCfg    int64  `json:"form_body_cap_bytes,omitempty"`

	logger     *zap.Logger
	secret     string
	difficulty int
	verifyPath string

	formDifficulty int
	formTokenTTL   time.Duration
	formMinFillMs  int64
	formScoring    string
	formBodyCap    int64
	replayLRU      *NonceLRU
}

// defaultReplayLRUSize bounds the per-machine seen-nonce set. Best-effort
// single-use — cluster-wide uniqueness is not attempted.
const defaultReplayLRUSize = 65536

func (*ChallengeApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "apx_challenge",
		New: func() caddy.Module { return new(ChallengeApp) },
	}
}

func (a *ChallengeApp) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()

	a.difficulty = a.DifficultyCfg
	if a.difficulty <= 0 {
		a.difficulty = defaultDifficulty
	}
	a.verifyPath = a.VerifyPathCfg
	if a.verifyPath == "" {
		a.verifyPath = defaultVerifyPath
	}
	a.secret = a.SecretCfg
	if a.secret == "" {
		return fmt.Errorf("apx_challenge app: secret is required (config key \"secret\")")
	}

	if a.formDifficulty = a.FormDifficultyCfg; a.formDifficulty <= 0 {
		a.formDifficulty = 14
	}
	if s := a.FormTokenTTLSecondsCfg; s > 0 {
		a.formTokenTTL = time.Duration(s) * time.Second
	} else {
		a.formTokenTTL = 600 * time.Second
	}
	if a.formMinFillMs = a.FormMinFillMsCfg; a.formMinFillMs <= 0 {
		a.formMinFillMs = 800
	}
	switch a.FormScoringCfg {
	case "off", "lenient", "strict":
		a.formScoring = a.FormScoringCfg
	default:
		a.formScoring = "lenient"
	}
	if a.formBodyCap = a.FormBodyCapBytesCfg; a.formBodyCap <= 0 {
		a.formBodyCap = 1 << 20
	}
	a.replayLRU = NewNonceLRU(defaultReplayLRUSize)

	return nil
}

func (a *ChallengeApp) Start() error { return nil }
func (a *ChallengeApp) Stop() error  { return nil }

func (a *ChallengeApp) Secret() string     { return a.secret }
func (a *ChallengeApp) Difficulty() int    { return a.difficulty }
func (a *ChallengeApp) VerifyPath() string { return a.verifyPath }

func (a *ChallengeApp) FormDifficulty() int         { return a.formDifficulty }
func (a *ChallengeApp) FormTokenTTL() time.Duration { return a.formTokenTTL }
func (a *ChallengeApp) FormMinFillMs() int64        { return a.formMinFillMs }
func (a *ChallengeApp) FormScoring() string         { return a.formScoring }
func (a *ChallengeApp) FormBodyCap() int64          { return a.formBodyCap }
func (a *ChallengeApp) ReplayLRU() *NonceLRU        { return a.replayLRU }

var (
	_ caddy.App         = (*ChallengeApp)(nil)
	_ caddy.Provisioner = (*ChallengeApp)(nil)
	_ AppRef            = (*ChallengeApp)(nil)
)
