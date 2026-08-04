package apxapp

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// puller replicates the fleet's maybepull.sh + pullscript.sh loop in-process:
// every tick it asks the control plane whether the cloud config is newer than
// the last one this instance loaded, and if so downloads the zipped config,
// extracts caddyconfig.json in memory, and POSTs it to the Caddy admin
// endpoint. All failures are logged and retried next tick; nothing crashes
// the Caddy process.
type puller struct {
	cfg         PullerConfig
	internalKey string // from APX_INTERNAL_KEY; never serialized
	st          *SharedState
	log         *zap.Logger
	client      *http.Client
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	tick        time.Duration
	consecFails int // only touched by the loop goroutine (read by tests after stop)

	startedMu sync.Mutex
	started   bool
}

// maxConfigEntrySize caps any zip entry we are willing to read (32 MiB).
const maxConfigEntrySize = 32 << 20

// consecFailThreshold is the consecutive-failure count at which the puller
// escalates from WARN to a single ERROR log.
const consecFailThreshold = 5

// newPuller resolves env fallbacks (construction time, never per-tick) and
// validates credentials. It does not start the loop; call start().
func newPuller(cfg PullerConfig, st *SharedState, log *zap.Logger) (*puller, error) {
	if log == nil {
		log = zap.NewNop()
	}
	if cfg.CheckURL == "" {
		cfg.CheckURL = os.Getenv("CALL_HOME_URL") + "/api/config-check"
	}
	if cfg.DownloadURL == "" {
		cfg.DownloadURL = os.Getenv("CALL_HOME_URL") + "/api/proxy-cluster/download-fly-config"
	}
	if cfg.ProxyServerID == "" {
		cfg.ProxyServerID = os.Getenv("PROXY_SERVER_ID")
	}
	if cfg.AdminEndpoint == "" {
		cfg.AdminEndpoint = "http://127.0.0.1:2019/load"
	}
	key := os.Getenv("APX_INTERNAL_KEY")
	if cfg.Enabled {
		if cfg.ProxyServerID == "" {
			return nil, errors.New("puller enabled but proxy server id is empty (set puller.proxy_server_id or PROXY_SERVER_ID)")
		}
		if key == "" {
			return nil, errors.New("puller enabled but internal key is empty (set APX_INTERNAL_KEY)")
		}
	}
	interval := cfg.IntervalSeconds
	if interval <= 0 {
		interval = 60
	}
	return &puller{
		cfg:         cfg,
		internalKey: key,
		st:          st,
		log:         log,
		// One client for the puller's lifetime: 20s timeout, default
		// transport so keep-alives stay on (the whole point vs curl).
		client: &http.Client{Timeout: 20 * time.Second},
		tick:   time.Duration(interval) * time.Second,
	}, nil
}

func (p *puller) start() {
	p.startedMu.Lock()
	defer p.startedMu.Unlock()
	if p.started {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.started = true
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.loop(ctx)
	}()
}

// stop cancels the loop and waits for the goroutine to exit. Idempotent and
// reload-safe: two pullers briefly overlapping cannot corrupt SharedState
// because lastStamp writes are mutex-guarded.
func (p *puller) stop() {
	p.startedMu.Lock()
	if !p.started {
		p.startedMu.Unlock()
		return
	}
	p.started = false
	cancel := p.cancel
	p.startedMu.Unlock()
	cancel()
	p.wg.Wait()
}

func (p *puller) running() bool {
	if p == nil {
		return false
	}
	p.startedMu.Lock()
	defer p.startedMu.Unlock()
	return p.started
}

func (p *puller) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(p.tick)):
		}
		p.checkOnce(ctx)
	}
}

// jitter spreads d by ±10% so a fleet of machines doesn't sync-hammer the
// control plane.
func jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.9 + 0.2*rand.Float64()))
}

// checkOnce runs one maybepull cycle: config-check, and on 200 the full
// download → unzip → admin-load pull.
func (p *puller) checkOnce(ctx context.Context) {
	stamp := p.st.LastStamp()
	if stamp == "" {
		stamp = "0"
	}
	url := fmt.Sprintf("%s/%s/%s", p.cfg.CheckURL, p.cfg.ProxyServerID, stamp)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		p.fail(ctx, "check", err)
		return
	}
	req.Header.Set("apx-internal-key", p.internalKey)
	resp, err := p.client.Do(req)
	if err != nil {
		p.fail(ctx, "check", err)
		return
	}
	switch resp.StatusCode {
	case http.StatusOK:
		// Newer config available; fall through to pull it.
	case http.StatusNoContent, http.StatusNotModified:
		// Up to date (mirrors maybepull.sh: only exactly 200 pulls).
		drain(resp)
		p.ok()
		return
	default:
		// 401/400/5xx etc. are real failures, not "up to date".
		code := resp.StatusCode
		drain(resp)
		p.fail(ctx, "check", fmt.Errorf("config check returned HTTP %d", code))
		return
	}

	// The control plane sends the new stamp as the plain-text 200 body
	// (an integer unix timestamp). Prefer it; fall back to the legacy
	// x-apx-config-stamp header, then to local time below.
	headerStamp := resp.Header.Get("x-apx-config-stamp")
	stampBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	resp.Body.Close()
	newStamp := strings.TrimSpace(string(stampBytes))
	if newStamp == "" {
		newStamp = headerStamp
	}

	body, err := p.download(ctx)
	if err != nil {
		p.fail(ctx, "download", err)
		return
	}
	cfgJSON, err := extractCaddyConfig(body)
	if err != nil {
		p.fail(ctx, "unzip", err)
		return
	}
	if err := p.load(ctx, cfgJSON); err != nil {
		p.fail(ctx, "load", err)
		return
	}

	if newStamp == "" {
		newStamp = strconv.FormatInt(time.Now().Unix(), 10)
	}
	p.st.SetLastStamp(newStamp)
	p.ok()
	p.log.Info("apx puller loaded new config",
		zap.String("stamp", newStamp),
		zap.Int("config_bytes", len(cfgJSON)))
}

func (p *puller) download(ctx context.Context) ([]byte, error) {
	url := fmt.Sprintf("%s/%s", p.cfg.DownloadURL, p.cfg.ProxyServerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("apx-key", p.internalKey)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("config download returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxConfigEntrySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxConfigEntrySize {
		return nil, fmt.Errorf("config zip exceeds %d bytes", maxConfigEntrySize)
	}
	return body, nil
}

// extractCaddyConfig pulls caddyconfig.json out of an in-memory zip. Entries
// with path separators / traversal in their names or larger than 32 MiB are
// rejected outright.
func extractCaddyConfig(zipBytes []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("opening config zip: %w", err)
	}
	for _, f := range zr.File {
		if strings.ContainsAny(f.Name, `/\`) || strings.Contains(f.Name, "..") {
			return nil, fmt.Errorf("config zip entry name %q rejected", f.Name)
		}
		if f.UncompressedSize64 > maxConfigEntrySize {
			return nil, fmt.Errorf("config zip entry %q exceeds %d bytes", f.Name, maxConfigEntrySize)
		}
	}
	for _, f := range zr.File {
		if f.Name != "caddyconfig.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("opening caddyconfig.json entry: %w", err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxConfigEntrySize+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("reading caddyconfig.json entry: %w", err)
		}
		if len(data) > maxConfigEntrySize {
			return nil, fmt.Errorf("caddyconfig.json exceeds %d bytes", maxConfigEntrySize)
		}
		if len(data) == 0 {
			return nil, errors.New("caddyconfig.json is empty")
		}
		return data, nil
	}
	return nil, errors.New("caddyconfig.json not found in config zip")
}

func (p *puller) load(ctx context.Context, cfgJSON []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.AdminEndpoint, bytes.NewReader(cfgJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("admin /load rejected the config (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

func (p *puller) fail(ctx context.Context, step string, err error) {
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return // shutting down; a canceled in-flight request is not a failure
	}
	p.consecFails++
	p.log.Warn("apx puller step failed",
		zap.String("step", step),
		zap.Int("consecutive_failures", p.consecFails),
		zap.Error(err))
	if p.consecFails == consecFailThreshold {
		p.log.Error("apx puller failing repeatedly; config sync is stalled",
			zap.Int("consecutive_failures", p.consecFails),
			zap.String("last_step", step),
			zap.Error(err))
	}
}

func (p *puller) ok() { p.consecFails = 0 }

func drain(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
}
