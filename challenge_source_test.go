package apxstats

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

// minute12 is 2026-11-08T12:00Z as a unix minute.
var minute12 = uint32(time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC).Unix() / 60)

func pinChallengeMinute(t *testing.T, m uint32) {
	t.Helper()
	old := challengeClockMin
	challengeClockMin = func() uint32 { return m }
	t.Cleanup(func() { challengeClockMin = old })
}

// resetChallengeLoss empties the process-wide loss map now and after the test,
// so no test's loss leaks into another test's batches.
func resetChallengeLoss(t *testing.T) {
	t.Helper()
	takeChallengeLoss()
	t.Cleanup(func() { takeChallengeLoss() })
}

func lossSnapshot() map[challengeLossKey]uint64 {
	challengeLoss.mu.Lock()
	defer challengeLoss.mu.Unlock()
	out := make(map[challengeLossKey]uint64, len(challengeLoss.m))
	for k, v := range challengeLoss.m {
		out[k] = v
	}
	return out
}

func encodeRows(t *testing.T, fn func(gz *gzip.Writer)) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	fn(gz)
	require.NoError(t, gz.Close())
	r, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	raw, err := readAll(r)
	require.NoError(t, err)
	return string(raw)
}

func requestWithVars(vars map[string]any) *http.Request {
	r := newRequestWithChallengeOutcome("POST", "/", "example.com", "")
	for k, v := range vars {
		caddyhttp.SetVar(r.Context(), k, v)
	}
	return r
}

func postedTypes(posts []capturedPost, typ string) []map[string]any {
	var out []map[string]any
	for _, p := range posts {
		for _, row := range p.rows {
			if row["_type"] == typ {
				out = append(out, row)
			}
		}
	}
	return out
}

func TestChallengeAttemptRowWireOrder(t *testing.T) {
	k := challengeAttemptKey{vhost: "example.com", ip: "203.0.113.7", outcome: "failed_proof", source: "automatic", tsMin: minute12}
	got := encodeRows(t, func(gz *gzip.Writer) {
		require.NoError(t, encodeChallengeAttemptRow(gz, 42, k, 3))
	})
	require.Equal(t, `{"_type":"challenge_attempt","ts":"2026-11-08T12:00:00Z","proxy_server_id":42,"vhost":"example.com","ip":"203.0.113.7","outcome":"failed_proof","source":"automatic","attempt_count":3}`+"\n", got)

	loss := encodeRows(t, func(gz *gzip.Writer) {
		require.NoError(t, encodeChallengeLossRow(gz, challengeLossEntry{ps: 42, minute: minute12, count: 2}))
	})
	require.Equal(t, `{"_type":"challenge_loss","ts":"2026-11-08T12:00:00Z","proxy_server_id":42,"lost_count":2}`+"\n", loss)
}

func TestMissingSourceVarEncodesEmpty(t *testing.T) {
	r := requestWithVars(map[string]any{"apx_challenge_outcome": "passed"})
	require.Equal(t, "", readChallengeSource(r))
	got := encodeRows(t, func(gz *gzip.Writer) {
		k := challengeAttemptKey{vhost: "v", ip: "1.2.3.4", outcome: "passed", source: readChallengeSource(r), tsMin: minute12}
		require.NoError(t, encodeChallengeAttemptRow(gz, 1, k, 1))
	})
	require.Contains(t, got, `"outcome":"passed","source":"","attempt_count":1`)
}

func TestUnknownSourceVarIsUnknown(t *testing.T) {
	for _, known := range challengeSources {
		require.Equal(t, known, readChallengeSource(requestWithVars(map[string]any{challengeSourceVarKey: known})))
	}
	require.Equal(t, "unknown", readChallengeSource(requestWithVars(map[string]any{challengeSourceVarKey: "bogus"})))
	require.Equal(t, "unknown", readChallengeSource(requestWithVars(map[string]any{challengeSourceVarKey: "Automatic"})))
	require.Equal(t, "unknown", readChallengeSource(requestWithVars(map[string]any{challengeSourceVarKey: 7})))
}

func TestSourceSplitsKeys(t *testing.T) {
	pinChallengeMinute(t, minute12)
	a := &StatsApp{}
	a.challengeMap = make(map[challengeAttemptKey]uint64)
	base := challengeAttemptKey{vhost: "v", ip: "1.2.3.4", outcome: "failed_proof"}
	for _, src := range []string{"automatic", "automatic", "staff", ""} {
		k := base
		k.source = src
		a.RecordChallengeAttempt(k)
	}
	require.Len(t, a.challengeMap, 3)
	k := base
	k.source, k.tsMin = "automatic", minute12
	require.Equal(t, uint64(2), a.challengeMap[k])
}

func TestChallengeRowCarriesRequestMinute(t *testing.T) {
	resetChallengeLoss(t)
	srv, posts := captureServer(t, 200)
	defer srv.Close()
	a := newTestApp(t, srv.URL, "secret")
	// Recorded in the 12:00 minute, flushed at the real (much later) time.
	pinChallengeMinute(t, minute12)
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: "1.2.3.4", outcome: "failed_proof", source: "automatic"})
	require.Greater(t, timeNowUnixMin(), minute12)
	a.flushOnce(0)
	rows := postedTypes(posts(), "challenge_attempt")
	require.Len(t, rows, 1)
	require.Equal(t, "2026-11-08T12:00:00Z", rows[0]["ts"])
	require.Equal(t, "automatic", rows[0]["source"])
}

func fillChallengeKeys(a *StatsApp, n int, outcome string, offset int) {
	for i := 0; i < n; i++ {
		a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: strconv.Itoa(offset + i), outcome: outcome})
	}
}

func newBareChallengeApp() *StatsApp {
	a := &StatsApp{ProxyServerIDValue: 42}
	a.challengeMap = make(map[challengeAttemptKey]uint64)
	return a
}

func TestPageKeysCapSilently(t *testing.T) {
	resetChallengeLoss(t)
	pinChallengeMinute(t, minute12)
	a := newBareChallengeApp()
	fillChallengeKeys(a, challengeMaxKeys, "issued_document", 0)
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: "new1", outcome: "issued_other"})
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: "new2", outcome: "not_shown_api"})
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: "new3", outcome: "issued"})
	require.Len(t, a.challengeMap, challengeMaxKeys)
	require.Equal(t, uint64(3), a.challengeOverflow)
	require.Empty(t, lossSnapshot(), "dropped page keys must not mark loss")
}

func TestPassKeysUseReserve(t *testing.T) {
	resetChallengeLoss(t)
	pinChallengeMinute(t, minute12)
	a := newBareChallengeApp()
	fillChallengeKeys(a, challengeMaxKeys, "issued_document", 0)
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: "pass", outcome: "passed"})
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: "fail", outcome: "failed_proof"})
	require.Len(t, a.challengeMap, challengeMaxKeys+2)
	k := challengeAttemptKey{vhost: "v", ip: "pass", outcome: "passed", tsMin: minute12}
	require.Equal(t, uint64(1), a.challengeMap[k])
	require.Empty(t, lossSnapshot())
}

func TestDroppedPassPastReserveMarksLoss(t *testing.T) {
	resetChallengeLoss(t)
	pinChallengeMinute(t, minute12)
	a := newBareChallengeApp()
	fillChallengeKeys(a, challengeMaxKeys, "issued_document", 0)
	fillChallengeKeys(a, challengeReserveKeys, "passed", 1_000_000)
	require.Len(t, a.challengeMap, challengeMaxKeys+challengeReserveKeys)
	require.Empty(t, lossSnapshot())

	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: "late", outcome: "passed"})
	require.Len(t, a.challengeMap, challengeMaxKeys+challengeReserveKeys)
	require.Equal(t, map[challengeLossKey]uint64{{ps: 42, minute: minute12}: 1}, lossSnapshot())

	// An existing key past the reserve still counts and marks nothing.
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: "1000000", outcome: "passed"})
	require.Equal(t, map[challengeLossKey]uint64{{ps: 42, minute: minute12}: 1}, lossSnapshot())
}

func recordAndDrain(t *testing.T, a *StatsApp, minute uint32, ip, outcome string) *shipJob {
	t.Helper()
	pinChallengeMinute(t, minute)
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: ip, outcome: outcome, source: "automatic"})
	body, rows, health, carry, ok := a.drainAndEncodeCarry(false)
	require.True(t, ok)
	t.Cleanup(func() { health.release() })
	return &shipJob{body: body, rows: rows, health: health, carry: carry}
}

func TestDroppedBatchMarksLossMinutes(t *testing.T) {
	resetChallengeLoss(t)
	srv, _ := captureServer(t, 200)
	defer srv.Close()
	a := newTestApp(t, srv.URL, "key")
	first := recordAndDrain(t, a, minute12+1, "1.1.1.1", "passed")
	// A page row in the same batch must not be counted as a loss.
	pinChallengeMinute(t, minute12+1)
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: "9.9.9.9", outcome: "issued_document"})
	body, rows, health, carry, ok := a.drainAndEncodeCarry(false)
	require.True(t, ok)
	defer health.release()
	second := &shipJob{body: body, rows: rows, health: health, carry: carry}
	third := recordAndDrain(t, a, minute12+3, "3.3.3.3", "failed_proof")

	a.shipQ = newShipQueue()
	a.enqueueShip(first)
	a.enqueueShip(second)
	require.Empty(t, lossSnapshot(), "nothing dropped yet")
	a.enqueueShip(third) // drops first

	require.Equal(t, map[challengeLossKey]uint64{{ps: 42, minute: minute12 + 1}: 1}, lossSnapshot())
}

func runShipLoopOnce(t *testing.T, a *StatsApp, jobs ...*shipJob) {
	t.Helper()
	a.shipQ = newShipQueue()
	for _, j := range jobs {
		a.enqueueShip(j)
	}
	a.shipDone = make(chan struct{})
	a.shutdownReady = make(chan struct{})
	a.tickCtx, a.tickCancel = context.WithCancel(context.Background())
	a.attemptCtx, a.attemptCancel = context.WithCancel(context.Background())
	t.Cleanup(a.tickCancel)
	t.Cleanup(a.attemptCancel)
	go a.shipLoop()
	a.shipQ.close()
	select {
	case <-a.shipDone:
	case <-time.After(5 * time.Second):
		t.Fatal("shipLoop did not finish")
	}
}

func TestFailedDeliveryMarksLossMinutes(t *testing.T) {
	resetChallengeLoss(t)
	srv, _ := captureServer(t, 401) // permanent failure
	defer srv.Close()
	a := newTestApp(t, srv.URL, "key")
	job := recordAndDrain(t, a, minute12+7, "7.7.7.7", "passed")
	runShipLoopOnce(t, a, job)
	require.EqualValues(t, 1, a.Dropped())
	require.Equal(t, map[challengeLossKey]uint64{{ps: 42, minute: minute12 + 7}: 1}, lossSnapshot())

	// A delivered batch marks nothing.
	takeChallengeLoss()
	ok, _ := captureServer(t, 200)
	defer ok.Close()
	b := newTestApp(t, ok.URL, "key")
	runShipLoopOnce(t, b, recordAndDrain(t, b, minute12+8, "8.8.8.8", "passed"))
	require.Empty(t, lossSnapshot())
}

func TestLossRowsRetainedUntilDelivered(t *testing.T) {
	resetChallengeLoss(t)
	bad, _ := captureServer(t, 401)
	defer bad.Close()
	good, posts := captureServer(t, 200)
	defer good.Close()

	addChallengeLoss(42, minute12+30, 2)
	failing := newTestApp(t, bad.URL, "key")
	failing.flushBatch(0, false)
	require.Equal(t, map[challengeLossKey]uint64{{ps: 42, minute: minute12 + 30}: 2}, lossSnapshot(),
		"an undelivered loss row stays pending")

	delivering := newTestApp(t, good.URL, "key")
	delivering.flushBatch(0, false)
	rows := postedTypes(posts(), "challenge_loss")
	require.Len(t, rows, 1)
	require.Equal(t, "2026-11-08T12:30:00Z", rows[0]["ts"])
	require.Equal(t, float64(42), rows[0]["proxy_server_id"])
	require.Equal(t, float64(2), rows[0]["lost_count"])
	require.Empty(t, lossSnapshot(), "delivered loss rows are cleared")
}

func TestLossMapBounded(t *testing.T) {
	resetChallengeLoss(t)
	total := uint64(0)
	for i := 0; i < challengeLossMaxMinutes+500; i++ {
		addChallengeLoss(42, minute12+uint32(i), 1)
		total++
	}
	// An older minute arriving at the bound is merged too, not dropped.
	addChallengeLoss(42, minute12-10, 1)
	total++
	snap := lossSnapshot()
	require.LessOrEqual(t, len(snap), challengeLossMaxMinutes)
	var sum uint64
	for _, v := range snap {
		sum += v
	}
	require.Equal(t, total, sum, "merging at the bound must keep every lost row")
}

func TestLossMapIsProcessWide(t *testing.T) {
	resetChallengeLoss(t)
	pinChallengeMinute(t, minute12+5)
	good, posts := captureServer(t, 200)
	defer good.Close()

	// The old instance records a loss and is never flushed again.
	old := newBareChallengeApp()
	fillChallengeKeys(old, challengeMaxKeys, "issued_document", 0)
	fillChallengeKeys(old, challengeReserveKeys, "passed", 1_000_000)
	old.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: "late", outcome: "failed_proof"})

	replacement := newTestApp(t, good.URL, "key")
	replacement.flushBatch(0, false)
	rows := postedTypes(posts(), "challenge_loss")
	require.Len(t, rows, 1)
	require.Equal(t, "2026-11-08T12:05:00Z", rows[0]["ts"])
	require.Equal(t, float64(42), rows[0]["proxy_server_id"])
}

func TestRetiredDeliveryFailureHandsLossToReplacement(t *testing.T) {
	resetChallengeLoss(t)
	bad, _ := captureServer(t, 401)
	defer bad.Close()
	good, posts := captureServer(t, 200)
	defer good.Close()

	retired := newTestApp(t, bad.URL, "key")
	pinChallengeMinute(t, minute12+40)
	retired.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: "4.4.4.4", outcome: "passed", source: "automatic"})
	addChallengeLoss(42, minute12+39, 1) // a pending loss the retired drain will carry
	retired.httpDeliveryPending = true
	retired.httpDeliveryDone = make(chan struct{})
	retired.deliverRetiredHTTP()
	require.EqualValues(t, 2, retired.Dropped(), "the attempt row and the loss row it carried")

	require.Equal(t, map[challengeLossKey]uint64{
		{ps: 42, minute: minute12 + 40}: 1,
		{ps: 42, minute: minute12 + 39}: 1,
	}, lossSnapshot())

	replacement := newTestApp(t, good.URL, "key")
	replacement.flushBatch(0, false)
	rows := postedTypes(posts(), "challenge_loss")
	require.Len(t, rows, 2)
	require.Equal(t, "2026-11-08T12:39:00Z", rows[0]["ts"])
	require.Equal(t, "2026-11-08T12:40:00Z", rows[1]["ts"])
	require.Empty(t, lossSnapshot())
}

func TestMonitorHeaderStillRecordsChallengeOutcome(t *testing.T) {
	app := &fakeApp{psID: 42}
	h := &StatsHandler{app: app}
	r := newRequestWithChallengeOutcome("POST", "/verify", "example.com", "")
	r.Header.Set("apx-monitor", "true")
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		caddyhttp.SetVar(r.Context(), "apx_challenge_outcome", "passed")
		caddyhttp.SetVar(r.Context(), challengeSourceVarKey, "automatic")
		w.WriteHeader(200)
		return nil
	})
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, next))

	keys := app.challengeSnapshot()
	require.Len(t, keys, 1, "a monitor-header verify must still record its outcome")
	require.Equal(t, "passed", keys[0].outcome)
	require.Equal(t, "automatic", keys[0].source)
	require.Empty(t, app.snapshot(), "the request counter must not move")
	require.Empty(t, app.reqEventSnapshot())
}

func TestHandlerRecordsSourceOnKey(t *testing.T) {
	app := &fakeApp{psID: 42}
	h := &StatsHandler{app: app}
	r := newRequestWithChallengeOutcome("POST", "/", "example.com", "failed")
	caddyhttp.SetVar(r.Context(), challengeSourceVarKey, "edge_sequence")
	caddyhttp.SetVar(r.Context(), "apx_challenge_reason", "proof")
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, nextHandler(403)))
	keys := app.challengeSnapshot()
	require.Len(t, keys, 1)
	require.Equal(t, "failed_proof", keys[0].outcome)
	require.Equal(t, "edge_sequence", keys[0].source)
}

func TestRecordChallengeAttemptAllocations(t *testing.T) {
	pinChallengeMinute(t, minute12)
	a := newBareChallengeApp()
	// Static, non-interned strings, as a request's would be.
	key := challengeAttemptKey{vhost: "example.com", ip: "203.0.113.7", outcome: "failed_proof", source: "automatic"}
	a.RecordChallengeAttempt(key)
	allocs := testing.AllocsPerRun(200, func() { a.RecordChallengeAttempt(key) })
	// Before this change: three string clones (vhost, ip, outcome). The
	// source is a package-level constant, so it adds none.
	require.LessOrEqual(t, allocs, 3.0)
}

func TestChallengeLossConcurrent(t *testing.T) {
	resetChallengeLoss(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				addChallengeLoss(42, minute12+uint32(i%50), 1)
				if i%100 == 0 {
					c := &challengeCarry{losses: takeChallengeLoss()}
					c.fail()
				}
			}
		}(g)
	}
	wg.Wait()
	var sum uint64
	for _, v := range lossSnapshot() {
		sum += v
	}
	require.Equal(t, uint64(8*500), sum)
}
