// Package apxstats is the unified Approximated Caddy module. Importing it
// registers the stats, trace, and challenge modules; subpackages register
// themselves via their init functions.
package apxstats

import (
	_ "github.com/Approximated-Inc/apx-caddy-stats/challenge"
	_ "github.com/Approximated-Inc/apx-caddy-stats/trace"
)
