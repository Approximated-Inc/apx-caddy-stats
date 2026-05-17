package apxstats

import "github.com/caddyserver/caddy/v2"

// Handler module registers here. The top-level StatsApp registers in
// app.go so the app and the handler can be imported independently.
func init() {
	caddy.RegisterModule(&StatsHandler{})
	caddy.RegisterModule(&L4Handler{})
}
