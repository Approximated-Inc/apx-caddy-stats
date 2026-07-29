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
	VerifyDifficulty() int
	VerifyTokenTTL() time.Duration
	VerifyMinFillMs() int64
	VerifyScoring() string
	VerifyBodyCap() int64
	// ReplayLRU is the process-wide, app-owned set of recently-seen verify-token
	// nonces. Shared across all verify routes so a token is single-use per machine.
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

	// VerifyDifficultyCfg / VerifyTokenTTLSecondsCfg / VerifyMinFillMsCfg /
	// VerifyScoringCfg / VerifyBodyCapBytesCfg carry the Edge Verify config
	// keys verify_difficulty / verify_token_ttl_seconds / verify_min_fill_ms /
	// verify_scoring / verify_body_cap_bytes. Same *Cfg-suffix convention as above.
	VerifyDifficultyCfg      int    `json:"verify_difficulty,omitempty"`
	VerifyTokenTTLSecondsCfg int    `json:"verify_token_ttl_seconds,omitempty"`
	VerifyMinFillMsCfg       int64  `json:"verify_min_fill_ms,omitempty"`
	VerifyScoringCfg         string `json:"verify_scoring,omitempty"`
	VerifyBodyCapBytesCfg    int64  `json:"verify_body_cap_bytes,omitempty"`

	logger     *zap.Logger
	secret     string
	difficulty int
	verifyPath string

	verifyDifficulty int
	verifyTokenTTL   time.Duration
	verifyMinFillMs  int64
	verifyScoring    string
	verifyBodyCap    int64
	replayLRU        *NonceLRU
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

	if a.verifyDifficulty = a.VerifyDifficultyCfg; a.verifyDifficulty <= 0 {
		a.verifyDifficulty = 14
	}
	if s := a.VerifyTokenTTLSecondsCfg; s > 0 {
		a.verifyTokenTTL = time.Duration(s) * time.Second
	} else {
		a.verifyTokenTTL = 600 * time.Second
	}
	if a.verifyMinFillMs = a.VerifyMinFillMsCfg; a.verifyMinFillMs <= 0 {
		a.verifyMinFillMs = 800
	}
	switch a.VerifyScoringCfg {
	case "off", "lenient", "strict":
		a.verifyScoring = a.VerifyScoringCfg
	default:
		a.verifyScoring = "lenient"
	}
	if a.verifyBodyCap = a.VerifyBodyCapBytesCfg; a.verifyBodyCap <= 0 {
		a.verifyBodyCap = 1 << 20
	}
	a.replayLRU = NewNonceLRU(defaultReplayLRUSize)

	return nil
}

func (a *ChallengeApp) Start() error { return nil }
func (a *ChallengeApp) Stop() error  { return nil }

func (a *ChallengeApp) Secret() string     { return a.secret }
func (a *ChallengeApp) Difficulty() int    { return a.difficulty }
func (a *ChallengeApp) VerifyPath() string { return a.verifyPath }

func (a *ChallengeApp) VerifyDifficulty() int         { return a.verifyDifficulty }
func (a *ChallengeApp) VerifyTokenTTL() time.Duration { return a.verifyTokenTTL }
func (a *ChallengeApp) VerifyMinFillMs() int64        { return a.verifyMinFillMs }
func (a *ChallengeApp) VerifyScoring() string         { return a.verifyScoring }
func (a *ChallengeApp) VerifyBodyCap() int64          { return a.verifyBodyCap }
func (a *ChallengeApp) ReplayLRU() *NonceLRU          { return a.replayLRU }

var (
	_ caddy.App         = (*ChallengeApp)(nil)
	_ caddy.Provisioner = (*ChallengeApp)(nil)
	_ AppRef            = (*ChallengeApp)(nil)
)
