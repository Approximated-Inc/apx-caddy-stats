package apxstats

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&StatsApp{})
}

// AppRef is what handlers depend on. Production code uses *StatsApp;
// tests inject a stub.
type AppRef interface {
	// Record adds the given counter delta to the entry identified by k.
	// Lock-free on the hot path once k is in the map.
	Record(k Key, delta CounterDelta)
	// ProxyServerID returns the cluster id this Caddy instance serves.
	ProxyServerID() uint32
}

// CounterDelta is what a single request contributes. The handler builds
// one of these per request and hands it to Record. Histograms are
// recorded as the bucket index that fires (LatBucket); we don't pass a
// 16-element array per request — only one bucket is ever non-zero.
type CounterDelta struct {
	BytesIn       uint64
	BytesOut      uint64
	DurationUs    uint64
	LatBucket     int // 0..HistogramBuckets-1
}

// IngestConfig describes where the app POSTs counter batches.
type IngestConfig struct {
	// URL is the absolute URL of the app endpoint that ingests batches.
	URL string `json:"url,omitempty"`
	// AuthEnvVar names the env var to source the shared secret from.
	// Default: APX_INTERNAL_KEY.
	AuthEnvVar string `json:"auth_env_var,omitempty"`
	// AuthHeader is the HTTP header the secret rides on. Default: apx-key.
	AuthHeader string `json:"auth_header,omitempty"`
	// FlushIntervalMs controls the periodic drain. Default 30000ms.
	FlushIntervalMs int `json:"flush_interval_ms,omitempty"`
	// MaxBufferRows caps the live counter map. New keys are dropped at the
	// cap; existing keys keep counting. Default 50000.
	MaxBufferRows int `json:"max_buffer_rows,omitempty"`
	// TimeoutMs bounds each POST. Default 10000ms.
	TimeoutMs int `json:"timeout_ms,omitempty"`
	// MaxRetries is the number of retries on POST failure before dropping
	// the batch. Default 3.
	MaxRetries int `json:"max_retries,omitempty"`
}

// StatsApp is the top-level Caddy App. One per Caddy process. Owns the
// counter map and the flush goroutine. Registered at module ID
// "apx_stats" so handlers fetch it via ctx.App("apx_stats").
type StatsApp struct {
	// ProxyServerIDValue identifies the Approximated cluster this Caddy
	// instance serves. Required.
	ProxyServerIDValue uint32 `json:"proxy_server_id"`

	// MachineID identifies which Caddy machine in the cluster this is.
	// Currently unused by the wire format (the app server tags by sender);
	// kept here for log/metric labels.
	MachineID string `json:"machine_id,omitempty"`

	// Ingest is required.
	Ingest *IngestConfig `json:"ingest,omitempty"`

	logger *zap.Logger
	secret string
	client *http.Client

	cfg ingestRuntime // resolved from Ingest with defaults applied

	mu       sync.Mutex
	counters map[Key]*Counter

	overflow         uint64    // count of distinct new keys dropped due to MaxBufferRows
	overflowLoggedAt time.Time // first-overflow log throttle (zero = never logged)
	dropped          uint64    // count of rows dropped after retry exhaustion

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

type ingestRuntime struct {
	url           string
	authHeader    string
	flushInterval time.Duration
	maxBuffer     int
	maxRetries    int
}

// CaddyModule registers the app at root ID "apx_stats".
func (*StatsApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "apx_stats",
		New: func() caddy.Module { return new(StatsApp) },
	}
}

// Provision validates config, reads the shared secret, builds the HTTP
// client, and initializes the counter map. Called by Caddy before Start.
func (a *StatsApp) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	if a.Ingest == nil {
		return fmt.Errorf("apx_stats app: ingest config is required")
	}
	if a.Ingest.URL == "" {
		return fmt.Errorf("apx_stats app: ingest.url is required")
	}
	if a.ProxyServerIDValue == 0 {
		return fmt.Errorf("apx_stats app: proxy_server_id is required")
	}

	envVar := a.Ingest.AuthEnvVar
	if envVar == "" {
		envVar = "APX_INTERNAL_KEY"
	}
	a.secret = os.Getenv(envVar)
	if a.secret == "" {
		return fmt.Errorf("apx_stats app: %s env var is empty", envVar)
	}

	a.cfg = ingestRuntime{
		url:           a.Ingest.URL,
		authHeader:    firstNonEmpty(a.Ingest.AuthHeader, "apx-key"),
		flushInterval: durationMs(a.Ingest.FlushIntervalMs, 30_000),
		maxBuffer:     intDefault(a.Ingest.MaxBufferRows, 50_000),
		maxRetries:    intDefault(a.Ingest.MaxRetries, 3),
	}

	a.client = &http.Client{
		Timeout: durationMs(a.Ingest.TimeoutMs, 10_000),
		Transport: &http.Transport{
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	a.counters = make(map[Key]*Counter, a.cfg.maxBuffer/8)
	a.stopCh = make(chan struct{})
	return nil
}

// Start launches the periodic flush goroutine.
func (a *StatsApp) Start() error {
	a.wg.Add(1)
	go a.flushLoop()
	return nil
}

// Stop signals the flush goroutine to drain once more and exit.
func (a *StatsApp) Stop() error {
	a.stopOnce.Do(func() { close(a.stopCh) })
	a.wg.Wait()
	return nil
}

// ProxyServerID exposes the cluster id to handlers.
func (a *StatsApp) ProxyServerID() uint32 { return a.ProxyServerIDValue }

// Record adds delta to the counter at k, inserting a new entry if absent.
//
// The whole call is taken under a.mu. An earlier version released the
// mutex before doing per-field atomic.Add on the *Counter, but that
// raced with flushOnce: between the unlock and the atomic.Add a
// concurrent flushOnce could swap the map and the encode loop could
// read the field, so the late add landed on a *Counter that was no
// longer reachable through the live map and had already been encoded
// without it — the increment was lost. Plain field reads in the
// encoder against atomic writes here was also a Go data race per the
// memory model, which `go test -race` would catch.
//
// Holding the mutex through the increments closes both: any Record that
// gets the lock before flushOnce completes its mutations before
// flushOnce can swap; any Record that gets the lock after flushOnce
// looks up from the new map. The "lock-free atomic add" was a premature
// optimization — at any traffic this module sees per machine, an
// uncontended mutex is sub-microsecond and dwarfed by the http-handler
// chain around it.
func (a *StatsApp) Record(k Key, delta CounterDelta) {
	a.mu.Lock()
	defer a.mu.Unlock()

	c, ok := a.counters[k]
	if !ok {
		if len(a.counters) >= a.cfg.maxBuffer {
			atomic.AddUint64(&a.overflow, 1)
			metricBufferOverflow.Inc()
			a.maybeLogOverflow()
			return
		}
		c = &Counter{}
		a.counters[k] = c
	}

	c.RequestCount++
	c.BytesIn += delta.BytesIn
	c.BytesOut += delta.BytesOut
	c.DurationUsSum += delta.DurationUs
	if i := delta.LatBucket; i >= 0 && i < HistogramBuckets {
		c.LatBuckets[i]++
	}
}

// maybeLogOverflow emits a single zap.Warn the first time the buffer
// hits its cap, and at most once per minute thereafter. Without this,
// overflow showed up only as a Prometheus counter — useful for graphs
// but invisible during incident response when an operator is reading
// logs. Called under a.mu (Record holds it through this path).
func (a *StatsApp) maybeLogOverflow() {
	now := time.Now()
	if !a.overflowLoggedAt.IsZero() && now.Sub(a.overflowLoggedAt) < time.Minute {
		return
	}
	a.overflowLoggedAt = now

	if a.logger != nil {
		a.logger.Warn("apx_stats: buffer overflow — dropping new counter keys",
			zap.Int("max_buffer_rows", a.cfg.maxBuffer),
			zap.Uint64("overflow_total", a.overflow),
		)
	}
}

// flushLoop runs until Stop is called. On each tick it drains the
// current counter map and ships it. On Stop it does one final drain so
// shutdown loses ≤ flushInterval of buffered counters.
func (a *StatsApp) flushLoop() {
	defer a.wg.Done()
	t := time.NewTicker(a.cfg.flushInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			a.flushOnce()
		case <-a.stopCh:
			a.flushOnce()
			return
		}
	}
}

// flushOnce swaps the live counter map for a fresh one, encodes the
// snapshot as gzipped NDJSON, and POSTs it.
func (a *StatsApp) flushOnce() {
	a.mu.Lock()
	if len(a.counters) == 0 {
		a.mu.Unlock()
		return
	}
	snap := a.counters
	a.counters = make(map[Key]*Counter, a.cfg.maxBuffer/8)
	a.mu.Unlock()

	metricBufferSize.Set(float64(len(snap)))

	body, err := encodeBatch(a.ProxyServerIDValue, snap)
	if err != nil {
		atomic.AddUint64(&a.dropped, uint64(len(snap)))
		metricDroppedRows.Add(float64(len(snap)))
		if a.logger != nil {
			a.logger.Warn("apx_stats: encode batch failed", zap.Error(err))
		}
		return
	}

	if err := a.shipWithRetry(body); err != nil {
		atomic.AddUint64(&a.dropped, uint64(len(snap)))
		metricDroppedRows.Add(float64(len(snap)))
		if a.logger != nil {
			a.logger.Warn("apx_stats: ship failed; dropping batch",
				zap.Int("rows", len(snap)),
				zap.Error(err),
			)
		}
	}
}

// shipWithRetry POSTs body. Retries on transport error or 5xx, with a
// short exponential backoff. 4xx responses are NOT retried — they
// indicate a wire-format/auth problem that retries won't fix.
func (a *StatsApp) shipWithRetry(body []byte) error {
	var lastErr error
	for attempt := 0; attempt <= a.cfg.maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff(attempt))
		}
		err := a.shipOnce(body)
		if err == nil {
			metricShipAttempts.WithLabelValues("ok").Inc()
			return nil
		}
		lastErr = err
		if isPermanent(err) {
			metricShipAttempts.WithLabelValues("permanent").Inc()
			return err
		}
		metricShipAttempts.WithLabelValues("transient").Inc()
	}
	return lastErr
}

func (a *StatsApp) shipOnce(body []byte) error {
	start := time.Now()
	defer func() {
		metricShipDuration.Observe(time.Since(start).Seconds())
	}()

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		a.cfg.url,
		bytes.NewReader(body),
	)
	if err != nil {
		return permanentErr{err}
	}
	req.Header.Set(a.cfg.authHeader, a.secret)
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := a.client.Do(req)
	if err != nil {
		return err // transport errors are transient
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// 4xx: don't retry. Auth or wire-format problem.
		return permanentErr{fmt.Errorf("ingest %d", resp.StatusCode)}
	default:
		return fmt.Errorf("ingest %d", resp.StatusCode)
	}
}

// permanentErr marks an error as not worth retrying.
type permanentErr struct{ error }

func isPermanent(err error) bool {
	_, ok := err.(permanentErr)
	return ok
}

// encodeBatch builds the gzipped NDJSON body for a snapshot. One JSON
// object per line. Histogram buckets are emitted sparsely — buckets with
// zero counts are omitted to keep the wire small.
func encodeBatch(proxyServerID uint32, snap map[Key]*Counter) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	for k, c := range snap {
		if err := encodeRow(gz, proxyServerID, k, c); err != nil {
			return nil, err
		}
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encodeRow writes one NDJSON line. Hand-rolled to avoid encoding/json
// reflection overhead per row and to handle the sparse histogram fields
// without an intermediate map allocation.
func encodeRow(w *gzip.Writer, ps uint32, k Key, c *Counter) error {
	var b strings.Builder
	b.Grow(256)
	b.WriteByte('{')

	writeString(&b, "ts", formatTs(k.TsUnixMin))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeUint32(&b, "vhost_id", k.VhostID)
	b.WriteByte(',')
	writeString(&b, "method", k.Method)
	b.WriteByte(',')
	writeUint16(&b, "status", k.Status)
	b.WriteByte(',')
	writeString(&b, "origin", k.Origin)
	b.WriteByte(',')
	writeString(&b, "country", k.Country)
	b.WriteByte(',')
	writeUint32(&b, "asn", k.ASN)
	b.WriteByte(',')
	writeUint64(&b, "request_count", c.RequestCount)
	b.WriteByte(',')
	writeUint64(&b, "bytes_in", c.BytesIn)
	b.WriteByte(',')
	writeUint64(&b, "bytes_out", c.BytesOut)
	b.WriteByte(',')
	writeUint64(&b, "duration_us_sum", c.DurationUsSum)

	for i, n := range c.LatBuckets {
		if n == 0 {
			continue
		}
		b.WriteByte(',')
		writeUint64(&b, histKey(i), n)
	}

	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

// writeString writes a JSON `"key":"val"` pair. `val` is JSON-string
// escaped via encoding/json fallback when needed; we expect ASCII-clean
// inputs (method, origin, country, ISO timestamp) so the fast path
// handles 99.9% of cases.
func writeString(b *strings.Builder, key, val string) {
	b.WriteByte('"')
	b.WriteString(key)
	b.WriteString(`":`)
	if needsJSONEscape(val) {
		b.WriteString(jsonEscape(val))
	} else {
		b.WriteByte('"')
		b.WriteString(val)
		b.WriteByte('"')
	}
}

func writeUint16(b *strings.Builder, key string, n uint16) {
	b.WriteByte('"')
	b.WriteString(key)
	b.WriteString(`":`)
	b.WriteString(strconv.FormatUint(uint64(n), 10))
}

func writeUint32(b *strings.Builder, key string, n uint32) {
	b.WriteByte('"')
	b.WriteString(key)
	b.WriteString(`":`)
	b.WriteString(strconv.FormatUint(uint64(n), 10))
}

func writeUint64(b *strings.Builder, key string, n uint64) {
	b.WriteByte('"')
	b.WriteString(key)
	b.WriteString(`":`)
	b.WriteString(strconv.FormatUint(n, 10))
}

func needsJSONEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == '"' || c == '\\' || c >= 0x80 {
			return true
		}
	}
	return false
}

// jsonEscape uses encoding/json's escaping rules via Marshal. The
// fast-path string writer handles >99% of inputs without taking this
// path, so the per-call cost is fine for the rare exotic header value.
func jsonEscape(s string) string {
	// Inlined minimal escaping. Avoids importing encoding/json just for
	// the slow path — keeps dependencies tight. Handles control chars,
	// quotes, backslashes; non-ASCII passes through (ECMA-404 allows it).
	var out strings.Builder
	out.Grow(len(s) + 2)
	out.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			out.WriteByte('\\')
			out.WriteByte(c)
		case c == '\n':
			out.WriteString(`\n`)
		case c == '\r':
			out.WriteString(`\r`)
		case c == '\t':
			out.WriteString(`\t`)
		case c < 0x20:
			fmt.Fprintf(&out, `\u%04x`, c)
		default:
			out.WriteByte(c)
		}
	}
	out.WriteByte('"')
	return out.String()
}

// firstNonEmpty returns the first non-empty string in args, or "".
func firstNonEmpty(args ...string) string {
	for _, s := range args {
		if s != "" {
			return s
		}
	}
	return ""
}

func intDefault(n, def int) int {
	if n > 0 {
		return n
	}
	return def
}

func durationMs(n, def int) time.Duration {
	if n <= 0 {
		n = def
	}
	return time.Duration(n) * time.Millisecond
}

// backoff returns a sleep duration for retry attempt i (1-indexed).
// 200ms, 800ms, 2.4s — bounded so a long flush doesn't cause the next
// tick to fire on top of an in-flight retry.
func backoff(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 200 * time.Millisecond
	case 2:
		return 800 * time.Millisecond
	default:
		return 2400 * time.Millisecond
	}
}

// Overflow returns the cumulative count of new keys dropped due to the
// buffer cap. Exposed for tests + observability.
func (a *StatsApp) Overflow() uint64 { return atomic.LoadUint64(&a.overflow) }

// Dropped returns the cumulative count of rows dropped after retry
// exhaustion or encode failure.
func (a *StatsApp) Dropped() uint64 { return atomic.LoadUint64(&a.dropped) }

var (
	_ caddy.App         = (*StatsApp)(nil)
	_ caddy.Provisioner = (*StatsApp)(nil)
	_ AppRef            = (*StatsApp)(nil)
)
