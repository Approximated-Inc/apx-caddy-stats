package apxtrace

import (
	"context"
	"os"

	"github.com/caddyserver/caddy/v2"
)

// fakeCaddyCtx returns a minimal caddy.Context for Provision tests that
// don't exercise ctx.App or ctx.Logger. We rely on Provision early-returning
// on config errors before touching the logger.
func fakeCaddyCtx() caddy.Context {
	c, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	return c
}

// envGet is a tiny indirection used by app_test.go to keep env access
// centralized and easy to stub if needed.
func envGet(name string) string { return os.Getenv(name) }
