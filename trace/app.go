package apxtrace

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&TraceApp{})
}

// AppRef is the interface handlers depend on. Production code uses *TraceApp,
// tests inject a fake that captures events in memory.
type AppRef interface {
	EmitEvent(evt Event, traceToken string)
	Secret() string
}

// EventSinkConfig describes where the plugin posts trace events.
type EventSinkConfig struct {
	// URL is the absolute URL of the app endpoint that ingests trace events.
	URL string `json:"url,omitempty"`
	// AuthEnvVar names an environment variable the plugin reads at Provision
	// to source the shared secret. Default: APX_INTERNAL_KEY.
	AuthEnvVar string `json:"auth_env_var,omitempty"`
	// AuthHeader is the HTTP header name the plugin sets the secret on for
	// every POST. Default: apx-key.
	AuthHeader string `json:"auth_header,omitempty"`
	// BufferSize is the bounded channel capacity for outbound events.
	BufferSize int `json:"buffer_size,omitempty"`
	// Concurrency is how many drain goroutines post events in parallel.
	Concurrency int `json:"concurrency,omitempty"`
	// TimeoutMs bounds each HTTP POST (default 5000ms).
	TimeoutMs int `json:"timeout_ms,omitempty"`
}

// TraceApp is the top-level Caddy App module that owns the HTTP event sink
// client and the shared HMAC secret used to validate trace tokens.
type TraceApp struct {
	EventSink *EventSinkConfig `json:"event_sink,omitempty"`

	logger  *zap.Logger
	secret  string
	client  *http.Client
	ch      chan outbound
	done    chan struct{}
	wg      sync.WaitGroup
	dropped uint64

	// shutdownOnce guards close(done) so Stop is idempotent.
	shutdownOnce sync.Once
}

type outbound struct {
	event Event
	token string
}

// CaddyModule returns the Caddy module info. Registered at root ID "apx_trace"
// so handlers can fetch it via ctx.App("apx_trace").
func (*TraceApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "apx_trace",
		New: func() caddy.Module { return new(TraceApp) },
	}
}

// Provision validates config, reads the shared secret from env, and builds
// the HTTP client + outbound channel. Called before Start.
func (a *TraceApp) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	if a.EventSink == nil {
		return fmt.Errorf("apx_trace app: event_sink config is required")
	}
	if a.EventSink.URL == "" {
		return fmt.Errorf("apx_trace app: event_sink.url is required")
	}

	envVar := a.EventSink.AuthEnvVar
	if envVar == "" {
		envVar = "APX_INTERNAL_KEY"
	}
	a.secret = os.Getenv(envVar)
	if a.secret == "" {
		return fmt.Errorf("apx_trace app: %s env var is empty", envVar)
	}

	bufSize := a.EventSink.BufferSize
	if bufSize <= 0 {
		bufSize = 512
	}
	timeoutMs := a.EventSink.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}

	a.client = &http.Client{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
		Transport: &http.Transport{
			MaxIdleConns:        20,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	a.ch = make(chan outbound, bufSize)
	a.done = make(chan struct{})
	return nil
}

// Start spawns the drain goroutines that POST buffered events.
func (a *TraceApp) Start() error {
	conc := 4
	if a.EventSink != nil && a.EventSink.Concurrency > 0 {
		conc = a.EventSink.Concurrency
	}
	for i := 0; i < conc; i++ {
		a.wg.Add(1)
		go a.drain()
	}
	return nil
}

// Stop signals drain goroutines to flush and exit. Idempotent.
func (a *TraceApp) Stop() error {
	a.shutdownOnce.Do(func() {
		close(a.done)
	})
	a.wg.Wait()
	return nil
}

// Secret returns the shared secret (for handlers validating tokens).
func (a *TraceApp) Secret() string { return a.secret }

// Dropped returns the cumulative count of dropped events.
func (a *TraceApp) Dropped() uint64 { return atomic.LoadUint64(&a.dropped) }

// EmitEvent enqueues an event for async delivery. Drops oldest on overflow.
// Never blocks the calling handler.
func (a *TraceApp) EmitEvent(evt Event, traceToken string) {
	ob := outbound{event: evt, token: traceToken}
	select {
	case a.ch <- ob:
	default:
		// Buffer full — drop oldest to make room for the new event.
		select {
		case <-a.ch:
			atomic.AddUint64(&a.dropped, 1)
			metricEventsDropped.Inc()
		default:
		}
		select {
		case a.ch <- ob:
		default:
			atomic.AddUint64(&a.dropped, 1)
			metricEventsDropped.Inc()
		}
	}
}

func (a *TraceApp) drain() {
	defer a.wg.Done()
	for {
		select {
		case ob := <-a.ch:
			a.post(ob)
		case <-a.done:
			// Drain remaining buffered events, then exit.
			for {
				select {
				case ob := <-a.ch:
					a.post(ob)
				default:
					return
				}
			}
		}
	}
}

func (a *TraceApp) post(ob outbound) {
	body, err := json.Marshal(ob.event)
	if err != nil {
		metricEventSinkErrors.Inc()
		if a.logger != nil {
			a.logger.Warn("apx_trace: marshal event", zap.Error(err))
		}
		return
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, a.EventSink.URL, bytes.NewReader(body))
	if err != nil {
		metricEventSinkErrors.Inc()
		return
	}
	authHeader := a.EventSink.AuthHeader
	if authHeader == "" {
		authHeader = "apx-key"
	}
	req.Header.Set(authHeader, a.secret)
	req.Header.Set("apx-trace-token", ob.token)
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := a.client.Do(req)
	if err != nil {
		metricEventSinkErrors.Inc()
		if a.logger != nil {
			a.logger.Debug("apx_trace: event sink POST failed", zap.Error(err))
		}
		return
	}
	defer resp.Body.Close()
	metricEventSinkDuration.Observe(time.Since(start).Seconds())

	if resp.StatusCode >= 400 {
		metricEventSinkErrors.Inc()
		if a.logger != nil {
			a.logger.Debug("apx_trace: event sink non-2xx",
				zap.Int("status", resp.StatusCode),
				zap.String("url", a.EventSink.URL),
			)
		}
		return
	}
	metricEventsEmittedTotal.WithLabelValues(ob.event.Type).Inc()
}

var (
	_ caddy.App         = (*TraceApp)(nil)
	_ caddy.Provisioner = (*TraceApp)(nil)
	_ AppRef            = (*TraceApp)(nil)
)
