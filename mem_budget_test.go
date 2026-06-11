package apxstats

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/require"
)

// stubRSS returns a readRSS func that always reports v.
func stubRSS(v uint64) func() (uint64, bool) {
	return func() (uint64, bool) { return v, true }
}

func TestMemGovernor_BudgetsFromTotalRAM(t *testing.T) {
	total := uint64(1 << 30)
	g := newMemGovernor(total, stubRSS(0), nil)
	require.Equal(t, total, g.totalRAM)
	require.Equal(t, uint64(bufferShareFraction*float64(total)), g.shareBudget)
	require.Equal(t, uint64(rssCeilingFraction*float64(total)), g.rssCeiling)
}

func TestMemGovernor_TryReserveBoundsShareBudget(t *testing.T) {
	g := newMemGovernor(1_000_000, stubRSS(0), nil) // share 400_000
	require.True(t, g.tryReserve(400_000), "reserving exactly the budget must succeed")
	require.False(t, g.tryReserve(1), "any byte past the share budget must be rejected")
	g.release(400_000)
	require.True(t, g.tryReserve(1), "released bytes return to the budget")
}

func TestMemGovernor_TryReserveZeroOrNegativeIsFree(t *testing.T) {
	g := newMemGovernor(1_000_000, stubRSS(0), nil)
	require.True(t, g.tryReserve(0))
	require.True(t, g.tryReserve(-5))
	require.Zero(t, g.bufferBytes.Load())
}

func TestMemGovernor_RSSCeilingGate(t *testing.T) {
	var rss atomic.Uint64
	read := func() (uint64, bool) { return rss.Load(), true }
	rss.Store(900_000) // ceiling = 800_000
	g := newMemGovernor(1_000_000, read, nil)
	require.False(t, g.tryReserve(1), "reserve must fail while cached RSS exceeds the ceiling")

	rss.Store(100_000)
	g.refreshRSS()
	require.True(t, g.tryReserve(1), "reserve recovers once RSS drops under the ceiling")
}

func TestMemGovernor_RSSReadFailureDegradesToShareBudget(t *testing.T) {
	g := newMemGovernor(1_000_000, func() (uint64, bool) { return 0, false }, nil)
	require.Zero(t, g.cachedRSS.Load(), "unreadable RSS must be treated as 0")
	require.True(t, g.tryReserve(400_000), "share budget alone still bounds")
	require.False(t, g.tryReserve(1))
	g.refreshRSS() // repeated failures must not panic (warn-once path)
}

func TestMemGovernor_Pressure_ShareComponent(t *testing.T) {
	g := newMemGovernor(1_000_000, stubRSS(0), nil) // share 400_000
	require.Zero(t, g.pressure())
	require.True(t, g.tryReserve(200_000))
	require.InDelta(t, 0.5, g.pressure(), 0.01)
	require.True(t, g.tryReserve(200_000))
	require.InDelta(t, 1.0, g.pressure(), 0.01)
}

func TestMemGovernor_Pressure_RSSComponent(t *testing.T) {
	var rss atomic.Uint64
	read := func() (uint64, bool) { return rss.Load(), true }
	rss.Store(100_000) // baseline
	g := newMemGovernor(1_000_000, read, nil)

	// Halfway from baseline (100K) to ceiling (800K) = 450K.
	rss.Store(450_000)
	g.refreshRSS()
	require.InDelta(t, 0.5, g.pressure(), 0.01)

	// Pressure is the max of the two components: share at 0.75 wins.
	require.True(t, g.tryReserve(300_000))
	require.InDelta(t, 0.75, g.pressure(), 0.01)
}

func TestMemGovernor_ReleaseClampsAtZero(t *testing.T) {
	g := newMemGovernor(1_000_000, stubRSS(0), nil)
	require.True(t, g.tryReserve(100))
	g.release(10_000) // over-release must not go negative
	require.GreaterOrEqual(t, g.bufferBytes.Load(), int64(0))
}

func TestMemGovernor_TryReserveConcurrent(t *testing.T) {
	g := newMemGovernor(1_000_000, stubRSS(0), nil) // share 400_000
	var reserved atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1_000; j++ {
				if g.tryReserve(100) {
					reserved.Add(100)
				}
			}
		}()
	}
	wg.Wait()
	require.Equal(t, reserved.Load(), g.bufferBytes.Load())
	require.LessOrEqual(t, g.bufferBytes.Load(), int64(g.shareBudget),
		"concurrent reserves must never exceed the share budget")
}

func TestMemGovernor_NextRefreshIntervalTightensUnderPressure(t *testing.T) {
	g := newMemGovernor(1_000_000, stubRSS(0), nil) // share 400_000
	require.Equal(t, rssRefreshInterval, g.nextRefreshInterval(), "no pressure → normal cadence")

	// Share pressure past pressureSampleStart (0.70) tightens the cadence.
	require.True(t, g.tryReserve(300_000)) // pressure 0.75
	require.Equal(t, rssRefreshPressureInterval, g.nextRefreshInterval())
	g.release(300_000)
	require.Equal(t, rssRefreshInterval, g.nextRefreshInterval(), "cadence relaxes when pressure subsides")

	// RSS pressure alone also tightens: baseline 100K, ceiling 800K.
	var rss atomic.Uint64
	read := func() (uint64, bool) { return rss.Load(), true }
	rss.Store(100_000)
	g2 := newMemGovernor(1_000_000, read, nil)
	require.Equal(t, rssRefreshInterval, g2.nextRefreshInterval())
	rss.Store(700_000) // (700K-100K)/(800K-100K) ≈ 0.86
	g2.refreshRSS()
	require.Equal(t, rssRefreshPressureInterval, g2.nextRefreshInterval())
}

func TestPressureSampleFloor(t *testing.T) {
	require.Equal(t, 1, pressureSampleFloor(0))
	require.Equal(t, 1, pressureSampleFloor(0.5))
	require.Equal(t, 1, pressureSampleFloor(pressureSampleStart))
	require.Equal(t, pressureSampleMaxFactor, pressureSampleFloor(1.0))
	require.Equal(t, pressureSampleFloor(1.0), pressureSampleFloor(1.7),
		"pressure past 1.0 clamps at the max factor")

	// Strictly between start and 1.0: a floor > 1, monotonic.
	mid := pressureSampleFloor(0.85)
	require.Greater(t, mid, 1)
	require.Less(t, mid, pressureSampleMaxFactor)
	require.GreaterOrEqual(t, pressureSampleFloor(0.95), mid)
}

func TestClampTotalRAM(t *testing.T) {
	require.Equal(t, uint64(fallbackTotalRAMBytes), clampTotalRAM(0, false), "detection failure → 256MB fallback")
	require.Equal(t, uint64(fallbackTotalRAMBytes), clampTotalRAM(0, true), "zero detection → 256MB fallback")
	require.Equal(t, uint64(minTotalRAMBytes), clampTotalRAM(64<<20, true), "implausibly small detection → 128MB floor")
	require.Equal(t, uint64(2<<30), clampTotalRAM(2<<30, true), "plausible detection passes through")
}

func TestParseStatmRSS(t *testing.T) {
	rss, ok := parseStatmRSS([]byte("12345 678 90 1 0 2 0\n"), 4096)
	require.True(t, ok)
	require.Equal(t, uint64(678*4096), rss)

	_, ok = parseStatmRSS([]byte("12345"), 4096)
	require.False(t, ok, "missing resident field")
	_, ok = parseStatmRSS([]byte("a b c"), 4096)
	require.False(t, ok, "non-numeric resident field")
	_, ok = parseStatmRSS([]byte(""), 4096)
	require.False(t, ok, "empty content")
	_, ok = parseStatmRSS([]byte("1 2 3"), 0)
	require.False(t, ok, "bad page size")
}

func TestParseCgroupMemMax(t *testing.T) {
	v, ok := parseCgroupMemMax([]byte("268435456\n"))
	require.True(t, ok)
	require.Equal(t, uint64(268435456), v)

	_, ok = parseCgroupMemMax([]byte("max\n"))
	require.False(t, ok, `"max" means no limit`)
	_, ok = parseCgroupMemMax([]byte(""))
	require.False(t, ok)
	_, ok = parseCgroupMemMax([]byte("garbage"))
	require.False(t, ok)
	_, ok = parseCgroupMemMax([]byte("0"))
	require.False(t, ok, "a zero limit is not a usable signal")
}

// The byte-accounting consts must cover the real struct sizes — if a
// field is added and these pins fail, bump the consts.
func TestRowFixedBytesCoverStructSizes(t *testing.T) {
	require.GreaterOrEqual(t, requestEventRowFixedBytes, int(unsafe.Sizeof(requestEventRow{})),
		"requestEventRowFixedBytes must cover unsafe.Sizeof(requestEventRow{})")
	require.GreaterOrEqual(t, corazaDetectionFixedBytes, int(unsafe.Sizeof(corazaDetection{})),
		"corazaDetectionFixedBytes must cover unsafe.Sizeof(corazaDetection{})")
}

// --- coraza detection slice under the governor ---

func TestRecordCorazaDetection_GovernorByteBudget(t *testing.T) {
	a := &StatsApp{}
	a.cfg.corazaMaxEvents = 10_000 // count cap not the binding constraint here
	a.memGov = newMemGovernor(100_000, stubRSS(0), nil)

	ev := corazaDetection{Severity: "CRITICAL", RuleMsg: strings.Repeat("x", 1000), RequestURI: "/a"}
	per := corazaDetectionBytes(&ev)
	fit := int(a.memGov.shareBudget) / per
	require.Positive(t, fit)

	const n = 100
	require.Greater(t, n, fit, "test must overrun the byte budget")
	for i := 0; i < n; i++ {
		a.RecordCorazaDetection(ev)
	}

	a.corazaMu.Lock()
	buffered := len(a.corazaEvents)
	overflow := a.corazaOverflow
	a.corazaMu.Unlock()
	require.Equal(t, fit, buffered, "events stop buffering at the byte budget")
	require.Equal(t, uint64(n-fit), overflow, "budget-rejected events count as overflow")
	require.Equal(t, int64(fit*per), a.memGov.bufferBytes.Load())

	snap := a.corazaSnapshot()
	require.Len(t, snap, fit)
	require.Zero(t, a.memGov.bufferBytes.Load(), "snapshot must release the reserved bytes")
	for i := 0; i < fit; i++ {
		a.RecordCorazaDetection(ev) // budget usable again next window
	}
	a.corazaMu.Lock()
	require.Len(t, a.corazaEvents, fit)
	a.corazaMu.Unlock()
}

func TestRecordCorazaDetection_RSSCeilingGate(t *testing.T) {
	a := &StatsApp{}
	a.cfg.corazaMaxEvents = 10
	a.memGov = newMemGovernor(1_000_000, stubRSS(900_000), nil) // RSS above the 800K ceiling

	a.RecordCorazaDetection(corazaDetection{RuleID: 1})
	require.Nil(t, a.corazaSnapshot(), "nothing may buffer while RSS is over the ceiling")
	a.corazaMu.Lock()
	defer a.corazaMu.Unlock()
	require.Equal(t, uint64(1), a.corazaOverflow)
}

// --- coraza row-width caps (truncate BEFORE buffering) ---

func TestBuildCorazaEvents_TruncatesWideFieldsBeforeBuffering(t *testing.T) {
	longMsg := strings.Repeat("m", corazaRuleMsgMaxBytes+100)
	longURI := "/" + strings.Repeat("u", corazaRequestURIMaxBytes+500)
	longHost := strings.Repeat("h", corazaRequestHostMaxBytes+50)
	d := &fakeMsgData{id: 1, msg: longMsg, severity: types.RuleSeverityWarning}
	al := &fakeAuditLog{
		tx: &fakeTx{
			unixTs:   1_700_000_000_000_000_000,
			id:       "tx-long",
			serverID: longHost,
			req:      &fakeReq{method: "GET", uri: longURI},
		},
		messages: []corazaMsgView{&fakeMsg{data: d}},
	}
	evs := buildCorazaEvents(al)
	require.Len(t, evs, 1)
	require.Len(t, evs[0].RuleMsg, corazaRuleMsgMaxBytes)
	require.Len(t, evs[0].RequestURI, corazaRequestURIMaxBytes)
	require.Len(t, evs[0].RequestHost, corazaRequestHostMaxBytes)
}

func TestBuildCorazaEvents_ShortFieldsUntouched(t *testing.T) {
	d := &fakeMsgData{id: 1, msg: "SQLi", severity: types.RuleSeverityWarning}
	al := buildAuditLog(1_700_000_000_000_000_000, "tx", "example.com", false, nil, d)
	evs := buildCorazaEvents(al)
	require.Len(t, evs, 1)
	require.Equal(t, "SQLi", evs[0].RuleMsg)
	require.Equal(t, "/x", evs[0].RequestURI)
	require.Equal(t, "example.com", evs[0].RequestHost)
}

// --- challenge map count cap ---

func TestRecordChallengeAttempt_CountCap(t *testing.T) {
	a := &StatsApp{}
	a.challengeMap = make(map[challengeAttemptKey]uint64)
	for i := 0; i < challengeMaxKeys; i++ {
		a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: strconv.Itoa(i), outcome: "issued"})
	}
	require.Len(t, a.challengeMap, challengeMaxKeys)

	// New key at cap: dropped + counted.
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "v", ip: "new-key", outcome: "issued"})
	require.Len(t, a.challengeMap, challengeMaxKeys, "new keys must not grow the map past the cap")
	require.Equal(t, uint64(1), a.challengeOverflow)

	// Existing key at cap: still counts.
	k := challengeAttemptKey{vhost: "v", ip: "0", outcome: "issued"}
	a.RecordChallengeAttempt(k)
	require.Equal(t, uint64(2), a.challengeMap[k])
	require.Equal(t, uint64(1), a.challengeOverflow, "existing-key increments are not overflow")
}
