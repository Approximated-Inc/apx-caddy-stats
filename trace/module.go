package apxtrace

import (
	"github.com/caddyserver/caddy/v2"
)

// Handler and transport modules register here. The top-level TraceApp module
// registers separately in app.go so the app can be provisioned independently.
func init() {
	caddy.RegisterModule(&TraceHandler{})
	caddy.RegisterModule(&MarkHandler{})
	caddy.RegisterModule(&TraceTransport{})
}
