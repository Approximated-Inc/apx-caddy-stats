package apxstats

import (
	"context"
	"net/http"
	"net/http/httptest"
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
