// Package apxapp provides the apps.apx Caddy app: the process-wide home for
// Approximated background machinery (config puller now; stats flush, defense
// rules feed, geo reader in later phases). State that must survive config
// reloads lives in a caddy.UsagePool, mirroring coraza-caddy's wafPool.
package apxapp

import (
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
)

func init() { caddy.RegisterModule(App{}) }

type PullerConfig struct {
	Enabled         bool `json:"enabled,omitempty"`
	IntervalSeconds int  `json:"interval_seconds,omitempty"`
	// CheckURL/DownloadURL/ProxyServerID default from the CALL_HOME_URL
	// and PROXY_SERVER_ID env vars in newPuller (Start time). The internal
	// key is deliberately NOT a config field: it comes only from
	// APX_INTERNAL_KEY so generated configs stay secret-free.
	CheckURL      string `json:"check_url,omitempty"`
	DownloadURL   string `json:"download_url,omitempty"`
	ProxyServerID string `json:"proxy_server_id,omitempty"`
	AdminEndpoint string `json:"admin_endpoint,omitempty"` // default http://127.0.0.1:2019/load
}

type App struct {
	Puller PullerConfig `json:"puller,omitempty"`
	Geo    GeoConfig    `json:"geo,omitempty"`

	logger *zap.Logger
	state  *SharedState
	puller *puller // nil unless enabled
	// geo is mmap'd at Provision and never explicitly closed (see geo.go
	// lifecycle note); nil when unconfigured or the file is unusable.
	geo *maxminddb.Reader
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "apx",
		New: func() caddy.Module { return new(App) },
	}
}

func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger(a)
	if a.Puller.IntervalSeconds <= 0 {
		a.Puller.IntervalSeconds = 60
	}
	st, err := loadSharedState()
	if err != nil {
		return fmt.Errorf("apx: loading shared state: %w", err)
	}
	a.state = st
	a.provisionGeo()
	return nil
}

func (a *App) Start() error {
	if a.Puller.Enabled {
		p, err := newPuller(a.Puller, a.state, a.logger)
		if err != nil {
			return fmt.Errorf("apx: puller: %w", err)
		}
		a.puller = p
		a.puller.start()
	}
	return nil
}

func (a *App) Stop() error {
	if a.puller != nil {
		a.puller.stop()
		a.puller = nil
	}
	return nil
}

func (a *App) PullerRunning() bool { return a.puller != nil && a.puller.running() }

// --- cross-reload shared state ---

var statePool = caddy.NewUsagePool()

type SharedState struct {
	mu        sync.Mutex
	lastStamp string
}

func (s *SharedState) Destruct() error { return nil }

func (s *SharedState) SetLastStamp(v string) { s.mu.Lock(); s.lastStamp = v; s.mu.Unlock() }
func (s *SharedState) LastStamp() string     { s.mu.Lock(); defer s.mu.Unlock(); return s.lastStamp }

func loadSharedState() (*SharedState, error) {
	val, _, err := statePool.LoadOrNew("apx.state", func() (caddy.Destructor, error) {
		return new(SharedState), nil
	})
	if err != nil {
		return nil, err
	}
	return val.(*SharedState), nil
}
