package apxstats

import (
	"github.com/caddyserver/caddy/v2"

	// Blank-import coraza-caddy so its init() registers the
	// http.handlers.waf Caddy module into the build, and so it's a DIRECT
	// dependency (xcaddy compiles this package into Caddy). The WAF
	// handler is what runs the rules and invokes ProcessLogging() on every
	// transaction; our audit-log writer (registered in coraza_writer.go's
	// init via coraza/v3's experimental plugins) is selected by the
	// generated `SecAuditLogType apx_stats` directive.
	_ "github.com/corazawaf/coraza-caddy/v2"
)

// Handler module registers here. The top-level StatsApp registers in
// app.go so the app and the handler can be imported independently.
func init() {
	caddy.RegisterModule(&StatsHandler{})
	caddy.RegisterModule(&L4Handler{})
	caddy.RegisterModule(&FingerprintHandler{})
}
