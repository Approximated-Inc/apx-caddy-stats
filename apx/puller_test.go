package apxapp

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// mkZip builds an in-memory zip archive with a single entry.
func mkZip(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	require.NoError(t, err)
	_, err = w.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// waitRecv receives from ch or fails the test after a deadline.
func waitRecv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

type checkReq struct {
	path        string
	internalKey string
}

type adminReq struct {
	body        string
	contentType string
}

// testPuller constructs a puller with a fast tick against the given config.
func testPuller(t *testing.T, cfg PullerConfig, st *SharedState) *puller {
	t.Helper()
	p, err := newPuller(cfg, st, zap.NewNop())
	require.NoError(t, err)
	p.tick = 10 * time.Millisecond
	return p
}

func TestPullerNoopOn204(t *testing.T) {
	t.Setenv("APX_INTERNAL_KEY", "test-key")

	checks := make(chan checkReq, 100)
	var downloads atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config-check/", func(w http.ResponseWriter, r *http.Request) {
		select {
		case checks <- checkReq{path: r.URL.Path, internalKey: r.Header.Get("apx-internal-key")}:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	ctl := httptest.NewServer(mux)
	defer ctl.Close()

	var adminPosts atomic.Int64
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminPosts.Add(1)
	}))
	defer admin.Close()

	st := &SharedState{}
	p := testPuller(t, PullerConfig{
		Enabled:       true,
		CheckURL:      ctl.URL + "/api/config-check",
		DownloadURL:   ctl.URL + "/dl",
		ProxyServerID: "42",
		AdminEndpoint: admin.URL + "/load",
	}, st)
	p.start()
	defer p.stop()

	first := waitRecv(t, checks, "first config-check request")
	require.Equal(t, "/api/config-check/42/0", first.path, "empty lastStamp must be sent as 0")
	require.Equal(t, "test-key", first.internalKey)

	second := waitRecv(t, checks, "second config-check request")
	require.Equal(t, "/api/config-check/42/0", second.path, "stamp must stay 0 while up to date")

	p.stop()
	require.Zero(t, downloads.Load(), "204 must not trigger a download")
	require.Zero(t, adminPosts.Load(), "204 must not trigger an admin load")
	require.Equal(t, "", st.LastStamp())
	require.Zero(t, p.consecFails, "successful up-to-date checks are not failures")
}

func TestPullerPullsAndLoadsOn200(t *testing.T) {
	t.Setenv("APX_INTERNAL_KEY", "test-key")

	const configJSON = `{"apps":{"http":{}}}`
	zipBytes := mkZip(t, "caddyconfig.json", configJSON)

	checks := make(chan checkReq, 100)
	dls := make(chan checkReq, 100)
	var served atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config-check/", func(w http.ResponseWriter, r *http.Request) {
		select {
		case checks <- checkReq{path: r.URL.Path, internalKey: r.Header.Get("apx-internal-key")}:
		default:
		}
		if served.CompareAndSwap(false, true) {
			w.Header().Set("x-apx-config-stamp", "1712345678")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		select {
		case dls <- checkReq{path: r.URL.Path, internalKey: r.Header.Get("apx-key")}:
		default:
		}
		w.Write(zipBytes)
	})
	ctl := httptest.NewServer(mux)
	defer ctl.Close()

	admins := make(chan adminReq, 100)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		buf.ReadFrom(r.Body)
		select {
		case admins <- adminReq{body: buf.String(), contentType: r.Header.Get("Content-Type")}:
		default:
		}
	}))
	defer admin.Close()

	st := &SharedState{}
	p := testPuller(t, PullerConfig{
		Enabled:       true,
		CheckURL:      ctl.URL + "/api/config-check",
		DownloadURL:   ctl.URL + "/dl",
		ProxyServerID: "42",
		AdminEndpoint: admin.URL + "/load",
	}, st)
	p.start()
	defer p.stop()

	got := waitRecv(t, admins, "admin /load POST")
	require.Equal(t, configJSON, got.body, "admin must receive the exact extracted JSON")
	require.Equal(t, "application/json", got.contentType)

	dl := waitRecv(t, dls, "download request")
	require.Equal(t, "/dl/42", dl.path)
	require.Equal(t, "test-key", dl.internalKey, "download must carry apx-key header")

	// After a successful load the check-response stamp is stored and used
	// on subsequent checks.
	deadline := time.After(5 * time.Second)
	for {
		var c checkReq
		select {
		case c = <-checks:
		case <-deadline:
			t.Fatal("timed out waiting for a config-check using the stored stamp")
		}
		if strings.HasSuffix(c.path, "/1712345678") {
			break
		}
	}
	require.Equal(t, "1712345678", st.LastStamp())
}

func TestPullerBadZipDoesNotCrash(t *testing.T) {
	t.Setenv("APX_INTERNAL_KEY", "test-key")

	dls := make(chan struct{}, 100)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config-check/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // always claims newer
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		select {
		case dls <- struct{}{}:
		default:
		}
		w.Write([]byte("this is not a zip archive"))
	})
	ctl := httptest.NewServer(mux)
	defer ctl.Close()

	var adminPosts atomic.Int64
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminPosts.Add(1)
	}))
	defer admin.Close()

	st := &SharedState{}
	p := testPuller(t, PullerConfig{
		Enabled:       true,
		CheckURL:      ctl.URL + "/api/config-check",
		DownloadURL:   ctl.URL + "/dl",
		ProxyServerID: "42",
		AdminEndpoint: admin.URL + "/load",
	}, st)
	p.start()

	waitRecv(t, dls, "first download attempt")
	waitRecv(t, dls, "second download attempt (loop survived the bad zip)")
	// A third attempt proves the first two cycles fully completed (their
	// failures were counted) before we stop.
	waitRecv(t, dls, "third download attempt")
	p.stop()

	require.Zero(t, adminPosts.Load(), "a bad zip must never reach the admin endpoint")
	require.Equal(t, "", st.LastStamp())
	require.GreaterOrEqual(t, p.consecFails, 2, "consecutive failures must be counted")
}

func TestPullerAdminRejectLogged(t *testing.T) {
	t.Setenv("APX_INTERNAL_KEY", "test-key")

	zipBytes := mkZip(t, "caddyconfig.json", `{"apps":{}}`)
	checks := make(chan checkReq, 100)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config-check/", func(w http.ResponseWriter, r *http.Request) {
		select {
		case checks <- checkReq{path: r.URL.Path}:
		default:
		}
		w.Header().Set("x-apx-config-stamp", "1712345678")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(zipBytes)
	})
	ctl := httptest.NewServer(mux)
	defer ctl.Close()

	admins := make(chan struct{}, 100)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case admins <- struct{}{}:
		default:
		}
		http.Error(w, `{"error":"unknown module"}`, http.StatusBadRequest)
	}))
	defer admin.Close()

	st := &SharedState{}
	p := testPuller(t, PullerConfig{
		Enabled:       true,
		CheckURL:      ctl.URL + "/api/config-check",
		DownloadURL:   ctl.URL + "/dl",
		ProxyServerID: "42",
		AdminEndpoint: admin.URL + "/load",
	}, st)
	p.start()

	waitRecv(t, admins, "first admin /load POST")
	waitRecv(t, admins, "second admin /load POST (loop retried next tick)")

	// The stamp must NOT be stored after a rejected load: every check keeps
	// sending 0.
	deadline := time.After(5 * time.Second)
	seen := 0
	for seen < 2 {
		var c checkReq
		select {
		case c = <-checks:
		case <-deadline:
			t.Fatal("timed out waiting for config-check requests")
		}
		require.True(t, strings.HasSuffix(c.path, "/0"),
			"lastStamp must not advance after a rejected load, got %s", c.path)
		seen++
	}
	p.stop()

	require.Equal(t, "", st.LastStamp())
	require.GreaterOrEqual(t, p.consecFails, 1)
}

func TestPullerStopIsClean(t *testing.T) {
	t.Setenv("APX_INTERNAL_KEY", "test-key")

	ctl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ctl.Close()

	st := &SharedState{}
	p := testPuller(t, PullerConfig{
		Enabled:       true,
		CheckURL:      ctl.URL + "/api/config-check",
		DownloadURL:   ctl.URL + "/dl",
		ProxyServerID: "42",
		AdminEndpoint: ctl.URL + "/load",
	}, st)

	require.False(t, p.running())
	p.start()
	require.True(t, p.running())

	done := make(chan struct{})
	go func() {
		p.stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop() did not return; goroutine leaked")
	}
	require.False(t, p.running())

	// stop is idempotent
	p.stop()
	require.False(t, p.running())
}

func TestPullerMissingCredsFailsFast(t *testing.T) {
	t.Setenv("CALL_HOME_URL", "")
	t.Setenv("PROXY_SERVER_ID", "")
	t.Setenv("APX_INTERNAL_KEY", "")

	st := &SharedState{}

	// no proxy server id anywhere
	_, err := newPuller(PullerConfig{
		Enabled:  true,
		CheckURL: "http://cp.example/api/config-check",
	}, st, zap.NewNop())
	require.Error(t, err)

	// id present but no internal key anywhere
	_, err = newPuller(PullerConfig{
		Enabled:       true,
		CheckURL:      "http://cp.example/api/config-check",
		ProxyServerID: "42",
	}, st, zap.NewNop())
	require.Error(t, err)

	// both present -> ok
	t.Setenv("APX_INTERNAL_KEY", "k")
	_, err = newPuller(PullerConfig{
		Enabled:       true,
		CheckURL:      "http://cp.example/api/config-check",
		ProxyServerID: "42",
	}, st, zap.NewNop())
	require.NoError(t, err)
}

func TestPullerEnvFallbacks(t *testing.T) {
	t.Setenv("CALL_HOME_URL", "http://cp.example")
	t.Setenv("PROXY_SERVER_ID", "77")
	t.Setenv("APX_INTERNAL_KEY", "sekret")

	p, err := newPuller(PullerConfig{Enabled: true}, &SharedState{}, zap.NewNop())
	require.NoError(t, err)
	require.Equal(t, "http://cp.example/api/config-check", p.cfg.CheckURL)
	require.Equal(t, "http://cp.example/api/proxy-cluster/download-fly-config", p.cfg.DownloadURL)
	require.Equal(t, "77", p.cfg.ProxyServerID)
	require.Equal(t, "http://127.0.0.1:2019/load", p.cfg.AdminEndpoint)
	require.Equal(t, "sekret", p.internalKey)
	require.Equal(t, 60*time.Second, p.tick, "interval defaults to 60s")
	require.NotNil(t, p.client)
	require.Equal(t, 20*time.Second, p.client.Timeout)
}

func TestPullerJitterBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := jitter(time.Second)
		require.GreaterOrEqual(t, d, 900*time.Millisecond)
		require.LessOrEqual(t, d, 1100*time.Millisecond)
	}
}

func TestExtractCaddyConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := extractCaddyConfig(mkZip(t, "caddyconfig.json", `{"apps":{}}`))
		require.NoError(t, err)
		require.Equal(t, `{"apps":{}}`, string(got))
	})

	t.Run("rejects traversal names", func(t *testing.T) {
		_, err := extractCaddyConfig(mkZip(t, "../caddyconfig.json", `{}`))
		require.Error(t, err)
		_, err = extractCaddyConfig(mkZip(t, "evil/caddyconfig.json", `{}`))
		require.Error(t, err)
	})

	t.Run("rejects missing entry", func(t *testing.T) {
		_, err := extractCaddyConfig(mkZip(t, "other.json", `{}`))
		require.Error(t, err)
	})

	t.Run("rejects empty entry", func(t *testing.T) {
		_, err := extractCaddyConfig(mkZip(t, "caddyconfig.json", ""))
		require.Error(t, err)
	})

	t.Run("rejects oversized entry", func(t *testing.T) {
		big := strings.Repeat("0", 32<<20+1)
		_, err := extractCaddyConfig(mkZip(t, "caddyconfig.json", big))
		require.Error(t, err)
	})

	t.Run("rejects garbage", func(t *testing.T) {
		_, err := extractCaddyConfig([]byte("not a zip"))
		require.Error(t, err)
	})
}
