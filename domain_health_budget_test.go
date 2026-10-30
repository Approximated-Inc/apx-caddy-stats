package apxstats

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func domainHealthBudgetGuard(t *testing.T) {
	t.Helper()
	require.Zero(t, domainHealthCredits.Load())
	require.False(t, domainHealthEncoding.Load())
	t.Cleanup(func() {
		require.Zero(t, domainHealthCredits.Load(), "all live, snapshot and queued credits must be released")
		require.False(t, domainHealthEncoding.Load(), "health encoder permit must be returned")
	})
}

func domainHealthBudgetApp(t *testing.T) *StatsApp {
	t.Helper()
	return newTestApp(t, "http://not-used.invalid", "k", func(a *StatsApp) { a.Ingest.MaxBufferRows = 50_000 })
}

func recordHealthKeys(a *StatsApp, first, count int) {
	for i := first; i < first+count; i++ {
		a.RecordDomainHealth(domainHealthKey{1, uint32(i + 1), strings.Repeat("a", 64)}, domainHealthCounter{RequestCount: 1, RoutingResponses: 1})
	}
}

func TestDomainHealthGlobalBudgetIncludesDetachedGenerations(t *testing.T) {
	domainHealthBudgetGuard(t)
	old, current := domainHealthBudgetApp(t), domainHealthBudgetApp(t)
	recordHealthKeys(old, 0, domainHealthResidentRecords+1)
	require.EqualValues(t, domainHealthResidentRecords, old.domainHealthKeys.Load())
	snapshot := old.drainDomainHealth()
	t.Cleanup(func() { snapshot.lease.release() })
	old.retireDomainHealth()
	recordHealthKeys(current, 0, 1)
	require.Zero(t, current.domainHealthKeys.Load(), "a detached retired snapshot still owns its credits")
	require.EqualValues(t, domainHealthResidentRecords, domainHealthCredits.Load())
	require.True(t, snapshot.lease.release())
	require.False(t, snapshot.lease.release(), "double release cannot free another generation's budget")
	recordHealthKeys(current, 0, 1)
	require.EqualValues(t, 1, current.domainHealthKeys.Load())
}

func TestDomainHealthGlobalBudgetConcurrentGenerations(t *testing.T) {
	domainHealthBudgetGuard(t)
	apps := []*StatsApp{domainHealthBudgetApp(t), domainHealthBudgetApp(t), domainHealthBudgetApp(t)}
	var writers sync.WaitGroup
	for _, app := range apps {
		for worker := 0; worker < 8; worker++ {
			writers.Add(1)
			go func(a *StatsApp, first int) {
				defer writers.Done()
				recordHealthKeys(a, first, 512)
			}(app, worker*512)
		}
	}
	writers.Wait()
	total := int64(0)
	for _, app := range apps {
		total += app.domainHealthKeys.Load()
	}
	require.EqualValues(t, domainHealthResidentRecords, total)
	require.Equal(t, total, domainHealthCredits.Load())
	for _, app := range apps {
		app.retireDomainHealth()
	}
	require.Zero(t, domainHealthCredits.Load())
}

func TestDomainHealthPressureRollsBackAllAdmission(t *testing.T) {
	domainHealthBudgetGuard(t)
	a := domainHealthBudgetApp(t)
	a.memGov.cachedRSS.Store(a.memGov.rssCeiling + 1)
	before := counterValue(metricDomainHealthDrops.WithLabelValues("pressure"))
	recordHealthKeys(a, 0, 1)
	require.Zero(t, a.domainHealthKeys.Load())
	require.Zero(t, domainHealthCredits.Load())
	require.Zero(t, a.memGov.bufferBytes.Load())
	require.Equal(t, before+1, counterValue(metricDomainHealthDrops.WithLabelValues("pressure")))
}

func TestDomainHealthQueuedCreditsReleaseOnEvictionAndDrop(t *testing.T) {
	domainHealthBudgetGuard(t)
	a := domainHealthBudgetApp(t)
	a.shipQ = newShipQueue()
	jobs := make([]*shipJob, 0, 3)
	for i := 0; i < 3; i++ {
		recordHealthKeys(a, i, 1)
		body, rows, lease, ok := a.drainAndEncode(false)
		require.True(t, ok)
		require.Equal(t, 1, rows)
		job := &shipJob{body: body, rows: rows, health: lease}
		jobs = append(jobs, job)
		a.enqueueShip(job)
	}
	require.True(t, jobs[0].health.released.Load())
	require.False(t, jobs[1].health.released.Load())
	require.EqualValues(t, 2, domainHealthCredits.Load(), "queued gzip bodies keep their credits")
	a.shipQ.close()
	a.dropQueued("")
	require.Zero(t, domainHealthCredits.Load())
	jobs[0].health.drop(domainHealthDropQueue)
	require.Zero(t, domainHealthCredits.Load())
}

func TestDomainHealthDeliveryReleasesCredits(t *testing.T) {
	for _, result := range []string{"success", "permanent", "transport", "cancelled"} {
		t.Run(result, func(t *testing.T) {
			domainHealthBudgetGuard(t)
			a := domainHealthBudgetApp(t)
			recordHealthKeys(a, 0, 1)
			body, rows, lease, ok := a.drainAndEncode(false)
			require.True(t, ok)
			entered := make(chan struct{}, 1)
			a.client = &http.Client{Transport: failureRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
				entered <- struct{}{}
				if result == "cancelled" {
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				if result == "transport" {
					return nil, io.EOF
				}
				status := 204
				if result == "permanent" {
					status = 401
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: r}, nil
			})}
			a.startShipper()
			t.Cleanup(a.tickCancel)
			t.Cleanup(a.attemptCancel)
			a.enqueueShip(&shipJob{body: body, rows: rows, health: lease})
			a.shipQ.close()
			if result == "cancelled" {
				<-entered
				require.EqualValues(t, 1, domainHealthCredits.Load())
				a.attemptCancel()
			}
			select {
			case <-a.shipDone:
			case <-time.After(3 * time.Second):
				t.Fatal("shipper did not finish")
			}
			require.True(t, lease.released.Load())
			require.Zero(t, domainHealthCredits.Load())
		})
	}
}

func TestDomainHealthRetryRequeueKeepsCredits(t *testing.T) {
	domainHealthBudgetGuard(t)
	a := domainHealthBudgetApp(t)
	recordHealthKeys(a, 0, 1)
	body, rows, lease, ok := a.drainAndEncode(false)
	require.True(t, ok)
	entered, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var retryCredits atomic.Int64
	a.client = &http.Client{Transport: failureRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-finish
			return nil, io.EOF
		}
		retryCredits.Store(domainHealthCredits.Load())
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: r}, nil
	})}
	a.startShipper()
	t.Cleanup(a.tickCancel)
	t.Cleanup(a.attemptCancel)
	a.enqueueShip(&shipJob{body: body, rows: rows, health: lease})
	a.shipQ.close()
	<-entered
	a.tickCancel()
	a.beginShutdownShipping()
	close(finish)
	select {
	case <-a.shipDone:
	case <-time.After(3 * time.Second):
		t.Fatal("retry did not finish")
	}
	require.EqualValues(t, 2, calls.Load())
	require.EqualValues(t, 1, retryCredits.Load(), "requeued body retains the original lease")
	require.Zero(t, domainHealthCredits.Load())
}

func TestDomainHealthEncoderPermitAndMixedFallback(t *testing.T) {
	domainHealthBudgetGuard(t)
	first, second := domainHealthBudgetApp(t), domainHealthBudgetApp(t)
	recordHealthKeys(first, 0, 1)
	snapshot := first.drainDomainHealth()
	frame := first.prepareDomainHealth(snapshot, domainHealthRawFrameBytes, domainHealthGzipFrameBytes)
	require.NotNil(t, frame)
	t.Cleanup(frame.finishEncoding)
	t.Cleanup(func() { frame.lease.release() })
	require.LessOrEqual(t, len(frame.raw), domainHealthRawFrameBytes)
	require.LessOrEqual(t, frame.gzipBytes, domainHealthGzipFrameBytes)
	recordHealthKeys(second, 1, 1)
	second.Record(Key{VhostID: 2, Status: 200}, CounterDelta{})
	body, rows, lease, ok := second.drainAndEncode(false)
	require.True(t, ok, "busy health encoder must preserve existing analytics")
	require.Nil(t, lease)
	require.Equal(t, 1, rows)
	reader, err := gzip.NewReader(bytes.NewReader(body))
	require.NoError(t, err)
	defer reader.Close()
	var row map[string]any
	require.NoError(t, json.NewDecoder(reader).Decode(&row))
	require.NotEqual(t, "domain_health", row["_type"])
	require.EqualValues(t, 1, domainHealthCredits.Load())
	frame.finishEncoding()
	recordHealthKeys(second, 2, 1)
	next := second.prepareDomainHealth(second.drainDomainHealth(), domainHealthRawFrameBytes, domainHealthGzipFrameBytes)
	require.NotNil(t, next)
	t.Cleanup(next.finishEncoding)
	t.Cleanup(func() { next.lease.release() })
	frame.finishEncoding()
	require.True(t, domainHealthEncoding.Load(), "double finish cannot release the next encoder's permit")
}

func TestDomainHealthFrameLimitFailureReturnsCredits(t *testing.T) {
	for _, limits := range []struct {
		name string
		raw, gzip int
	}{{"raw", 1, domainHealthGzipFrameBytes}, {"gzip", domainHealthRawFrameBytes, 1}} {
		t.Run(limits.name, func(t *testing.T) {
			domainHealthBudgetGuard(t)
			a := domainHealthBudgetApp(t)
			recordHealthKeys(a, 0, 1)
			require.Nil(t, a.prepareDomainHealth(a.drainDomainHealth(), limits.raw, limits.gzip))
			require.Zero(t, domainHealthCredits.Load())
			require.False(t, domainHealthEncoding.Load())
		})
	}
}

func TestDomainHealthEncodingDoesNotHoldRequestShard(t *testing.T) {
	domainHealthBudgetGuard(t)
	a := domainHealthBudgetApp(t)
	recordHealthKeys(a, 0, 1)
	snapshot := a.drainDomainHealth()
	shard := a.shards[1&shardMask]
	shard.mu.Lock()
	done := make(chan *domainHealthFrame, 1)
	go func() { done <- a.prepareDomainHealth(snapshot, domainHealthRawFrameBytes, domainHealthGzipFrameBytes) }()
	select {
	case frame := <-done:
		shard.mu.Unlock()
		require.NotNil(t, frame)
		frame.finishEncoding()
		frame.lease.release()
	case <-time.After(time.Second):
		shard.mu.Unlock()
		frame := <-done
		if frame != nil {
			frame.finishEncoding()
			frame.lease.release()
		}
		t.Fatal("health encoding waited for a request shard lock")
	}
}

func TestDomainHealthRetirementCancelsPreparedAndNewHealth(t *testing.T) {
	domainHealthBudgetGuard(t)
	a := domainHealthBudgetApp(t)
	recordHealthKeys(a, 0, 1)
	frame := a.prepareDomainHealth(a.drainDomainHealth(), domainHealthRawFrameBytes, domainHealthGzipFrameBytes)
	require.NotNil(t, frame)
	defer frame.finishEncoding()
	require.NoError(t, a.Stop())
	require.NoError(t, a.Stop())
	var output bytes.Buffer
	require.NoError(t, frame.writeTo(&output))
	require.Empty(t, output.Bytes())
	require.Zero(t, domainHealthCredits.Load())
	recordHealthKeys(a, 1, 10)
	require.Zero(t, a.domainHealthKeys.Load())
	require.Zero(t, a.memGov.bufferBytes.Load())
	select {
	case <-a.httpDeliveryDone:
	case <-time.After(3 * time.Second):
		t.Fatal("retired delivery did not finish")
	}
}

func TestDomainHealthStopKeepsExistingWaitBound(t *testing.T) {
	domainHealthBudgetGuard(t)
	a := domainHealthBudgetApp(t)
	a.cfg.stopWait = 20 * time.Millisecond
	a.cfg.flushInterval = time.Hour
	recordHealthKeys(a, 0, 1)
	require.NoError(t, a.Start())
	shard := a.shards[1&shardMask]
	shard.mu.Lock()
	locked := true
	defer func() {
		if locked {
			shard.mu.Unlock()
		}
	}()
	done := make(chan error, 1)
	go func() { done <- a.Stop() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("health cleanup blocked Stop behind an analytics shard")
	}
	require.True(t, a.domainHealthRetired.Load())
	require.EqualValues(t, 1, domainHealthCredits.Load(), "blocked drain retains its bounded credit")
	shard.mu.Unlock()
	locked = false
	select {
	case <-a.httpDeliveryDone:
	case <-time.After(3 * time.Second):
		t.Fatal("health cleanup did not finish after shard release")
	}
	require.Zero(t, domainHealthCredits.Load())
}

func TestDomainHealthBoundedBufferHardLimits(t *testing.T) {
	for _, limit := range []int{domainHealthRawFrameBytes, domainHealthGzipFrameBytes} {
		buffer := &domainHealthBuffer{limit: limit}
		_, err := io.Copy(buffer, strings.NewReader(strings.Repeat("x", limit)))
		require.NoError(t, err)
		require.Equal(t, limit, buffer.Len())
		require.LessOrEqual(t, cap(buffer.data), limit)
		_, err = buffer.Write([]byte("x"))
		require.ErrorIs(t, err, errDomainHealthFrameLimit)
		require.Equal(t, limit, buffer.Len())
	}
}

