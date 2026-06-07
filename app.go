package apxchallenge

import (
	"fmt"

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

	logger     *zap.Logger
	secret     string
	difficulty int
	verifyPath string
}

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
	return nil
}

func (a *ChallengeApp) Start() error { return nil }
func (a *ChallengeApp) Stop() error  { return nil }

func (a *ChallengeApp) Secret() string     { return a.secret }
func (a *ChallengeApp) Difficulty() int    { return a.difficulty }
func (a *ChallengeApp) VerifyPath() string { return a.verifyPath }

var (
	_ caddy.App         = (*ChallengeApp)(nil)
	_ caddy.Provisioner = (*ChallengeApp)(nil)
	_ AppRef            = (*ChallengeApp)(nil)
)
