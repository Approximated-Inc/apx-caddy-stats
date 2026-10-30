package apxstats

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func postedHealthVhosts(posts []capturedPost) map[float64]int {
	vhosts := map[float64]int{}
	for _, p := range posts {
		for _, row := range p.rows {
			if row["_type"] == "domain_health" {
				vhosts[row["vhost_id"].(float64)] += int(row["request_count"].(float64))
			}
		}
	}
	return vhosts
}

// A reload must ship the old generation's health like its other HTTP
// analytics: buffered rows in the final drain, late rows in retired delivery.
func TestDomainHealthStopShipsFinalAndLateHealth(t *testing.T) {
	domainHealthBudgetGuard(t)
	server, posts := captureServer(t, 200)
	defer server.Close()
	a := newTestApp(t, server.URL, "key", func(a *StatsApp) { a.Ingest.MaxBufferRows = 1000 })
	a.cfg.flushInterval = time.Hour
	recordHealthKeys(a, 0, 1)
	require.NoError(t, a.Start())
	require.NoError(t, a.Stop())
	require.NoError(t, a.Cleanup(), "Caddy cleans up a started app right after Stop")
	recordHealthKeys(a, 1, 1) // a request still in flight at reload
	a.finishHTTPRecord()
	awaitHTTPRetirementIdle(t, a)
	select {
	case <-a.shipDone:
	case <-time.After(5 * time.Second):
		t.Fatal("final ship did not finish")
	}
	require.Equal(t, map[float64]int{1: 1, 2: 1}, postedHealthVhosts(posts()))
	require.Zero(t, domainHealthCredits.Load())
}

// Caddy never stops an app whose Start did not run, so Cleanup must release
// the credits that requests already reserved in that generation.
func TestDomainHealthCleanupReleasesUnstartedGeneration(t *testing.T) {
	domainHealthBudgetGuard(t)
	a := domainHealthBudgetApp(t)
	recordHealthKeys(a, 0, 3)
	require.EqualValues(t, 3, domainHealthCredits.Load())
	require.NoError(t, a.Cleanup())
	require.Zero(t, domainHealthCredits.Load())
	require.Zero(t, a.domainHealthKeys.Load())
	require.Zero(t, a.memGov.bufferBytes.Load())
	recordHealthKeys(a, 3, 1)
	require.Zero(t, domainHealthCredits.Load(), "a cleaned-up generation admits no new keys")
}

// Retirement can land while a request waits for its shard lock; the re-check
// under the lock keeps it from admitting a key that no drain will release.
func TestDomainHealthRetirementRecheckedUnderShardLock(t *testing.T) {
	domainHealthBudgetGuard(t)
	a := domainHealthBudgetApp(t)
	shard := a.shards[1&shardMask]
	shard.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		recordHealthKeys(a, 0, 1) // vhost 1
	}()
	require.Eventually(t, func() bool { return goroutineBlockedInRecordHealth() }, 3*time.Second, time.Millisecond)
	a.domainHealthRetired.Store(true)
	shard.mu.Unlock()
	<-done
	require.Zero(t, a.domainHealthKeys.Load())
	require.Zero(t, domainHealthCredits.Load())
	require.Empty(t, shard.domainHealth)
}

func goroutineBlockedInRecordHealth() bool {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "(*StatsApp).RecordDomainHealth") && strings.Contains(g, "sync.(*Mutex)") {
			return true
		}
	}
	return false
}

func TestDomainHealthEncodeErrorDropsCredits(t *testing.T) {
	domainHealthBudgetGuard(t)
	original := encodeBatchFn
	t.Cleanup(func() { encodeBatchFn = original })
	encodeBatchFn = func(batchParts, uint32, uint32, map[Key]*Counter, map[uniqueKey]map[uint64]struct{}, map[L4SniKey]*l4SniCounter, l4IpSnap, map[fingerprintKey]*fingerprintCounter, map[fingerprintIpKey]*fingerprintCounter, []corazaDetection, map[challengeAttemptKey]uint64, map[edgeVerifyAttemptKey]uint64, []requestEventRow, ...map[l4BlockKey]uint64) ([]byte, error) {
		return nil, errors.New("encode failed")
	}
	a := domainHealthBudgetApp(t)
	recordHealthKeys(a, 0, 1)
	a.Record(Key{VhostID: 2, Status: 200}, CounterDelta{})
	before := counterValue(metricDomainHealthDrops.WithLabelValues("encode_error"))
	body, rows, lease, ok := a.drainAndEncode(false)
	require.False(t, ok)
	require.Nil(t, body)
	require.Zero(t, rows)
	require.Nil(t, lease)
	require.Zero(t, domainHealthCredits.Load(), "a failed encode releases its health credits")
	require.False(t, domainHealthEncoding.Load())
	require.Equal(t, before+1, counterValue(metricDomainHealthDrops.WithLabelValues("encode_error")))
}
