package apxstats

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type lbNextFn func(http.ResponseWriter, *http.Request) error

func (f lbNextFn) ServeHTTP(w http.ResponseWriter, r *http.Request) error { return f(w, r) }

func lbRequestWithReplacer() (*http.Request, *caddy.Replacer) {
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	return r.WithContext(ctx), repl
}

func TestLBRecorderRecordsServedUpstream(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	r, repl := lbRequestWithReplacer()
	next := lbNextFn(func(http.ResponseWriter, *http.Request) error {
		repl.Set("http.reverse_proxy.upstream.hostport", "10.0.0.1:443")
		repl.Set("http.reverse_proxy.upstream.latency", 75*time.Millisecond)
		return nil
	})

	if err := (LatencyRecorder{}).ServeHTTP(httptest.NewRecorder(), r, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	score, known := lbScore("10.0.0.1:443")
	if !known || score != float64(75*time.Millisecond) {
		t.Fatalf("got (%v, %v), want (75ms, true)", score, known)
	}
}

func TestLBRecorderIgnoresDialFailure(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	r, repl := lbRequestWithReplacer()
	// A dial failure sets hostport but never upstream.latency, because no
	// response ever came back. Recording it would make a fast failure look
	// like the fastest upstream and win every future selection.
	next := lbNextFn(func(http.ResponseWriter, *http.Request) error {
		repl.Set("http.reverse_proxy.upstream.hostport", "10.0.0.9:443")
		return nil
	})

	_ = (LatencyRecorder{}).ServeHTTP(httptest.NewRecorder(), r, next)

	if _, known := lbScore("10.0.0.9:443"); known {
		t.Fatal("dial failure must not produce a latency sample")
	}
}

// A 502/503/504 is a completed round-trip as far as Caddy is concerned:
// upstream.latency is set, and with no unhealthy_status on the passive
// health check nothing strikes the upstream either. An overloaded origin
// fast-failing at 2ms must not score as the fastest upstream.
func TestLBRecorderPenalizesServedGatewayError(t *testing.T) {
	for _, code := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			clock := time.Unix(0, 0)
			withLBClock(t, &clock)

			r, repl := lbRequestWithReplacer()
			next := lbNextFn(func(http.ResponseWriter, *http.Request) error {
				repl.Set("http.reverse_proxy.upstream.hostport", "10.0.0.2:443")
				repl.Set("http.reverse_proxy.upstream.latency", 2*time.Millisecond)
				repl.Set("http.reverse_proxy.status_code", code)
				return nil
			})

			if err := (LatencyRecorder{}).ServeHTTP(httptest.NewRecorder(), r, next); err != nil {
				t.Fatalf("ServeHTTP: %v", err)
			}
			score, known := lbScore("10.0.0.2:443")
			if !known {
				t.Fatal("a served error response must still produce a sample")
			}
			if score < float64(lbErrorPenalty) {
				t.Fatalf("got %v, want at least the %v penalty — a fast %d must not look like the fastest upstream", time.Duration(score), lbErrorPenalty, code)
			}
		})
	}
}

// The penalty is a floor, not a replacement: a 504 that took longer than
// the penalty records the time it actually took.
func TestLBRecorderPenaltyIsAFloor(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	slow := lbErrorPenalty + 3*time.Second
	r, repl := lbRequestWithReplacer()
	next := lbNextFn(func(http.ResponseWriter, *http.Request) error {
		repl.Set("http.reverse_proxy.upstream.hostport", "10.0.0.3:443")
		repl.Set("http.reverse_proxy.upstream.latency", slow)
		repl.Set("http.reverse_proxy.status_code", http.StatusGatewayTimeout)
		return nil
	})

	_ = (LatencyRecorder{}).ServeHTTP(httptest.NewRecorder(), r, next)

	if score, _ := lbScore("10.0.0.3:443"); score != float64(slow) {
		t.Fatalf("got %v, want the observed %v", time.Duration(score), slow)
	}
}

// Only gateway errors are penalised. A 500 is the origin answering (however
// unhappily) and a 404 is a perfectly good fast response; both record the
// observed latency.
func TestLBRecorderKeepsObservedLatencyForOtherStatuses(t *testing.T) {
	for _, code := range []int{http.StatusOK, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			clock := time.Unix(0, 0)
			withLBClock(t, &clock)

			r, repl := lbRequestWithReplacer()
			next := lbNextFn(func(http.ResponseWriter, *http.Request) error {
				repl.Set("http.reverse_proxy.upstream.hostport", "10.0.0.4:443")
				repl.Set("http.reverse_proxy.upstream.latency", 2*time.Millisecond)
				repl.Set("http.reverse_proxy.status_code", code)
				return nil
			})

			_ = (LatencyRecorder{}).ServeHTTP(httptest.NewRecorder(), r, next)

			score, known := lbScore("10.0.0.4:443")
			if !known || score != float64(2*time.Millisecond) {
				t.Fatalf("got (%v, %v), want (2ms, true) for status %d", time.Duration(score), known, code)
			}
		})
	}
}

func TestLBRecorderPropagatesNextError(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	r, _ := lbRequestWithReplacer()
	want := caddyhttp.Error(http.StatusBadGateway, http.ErrAbortHandler)
	next := lbNextFn(func(http.ResponseWriter, *http.Request) error { return want })

	if got := (LatencyRecorder{}).ServeHTTP(httptest.NewRecorder(), r, next); got != want {
		t.Fatalf("got %v, want the error from next", got)
	}
}
