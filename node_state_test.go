package apxstats

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func nodeStateRowJSON(t *testing.T, m nodeStateMinute) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	require.NoError(t, encodeNodeStateRow(gz, 768, "e2865013c51398", m))
	require.NoError(t, gz.Close())
	r, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

// B6: golden wire format.
func TestNodeStateRowGolden(t *testing.T) {
	ts := uint32(time.Date(2026, 10, 28, 17, 10, 0, 0, time.UTC).Unix() / 60)
	m := nodeStateMinute{
		ts: ts, levelMax: 2, l1Seconds: 40, l2Seconds: 20, reasons: 3, schedP99UsMax: 180000,
		burstEstSMin: -1, burstModel: "uncalibrated", inflightMax: 412, admissionLimitMin: 24,
		gomaxprocs: 1,
	}
	m.counts[nsWafSkippedDetect] = 5120
	m.counts[nsShedP1] = 3
	m.counts[nsShedP2] = 88
	m.counts[nsShedP3] = 940
	require.Equal(t,
		`{"_type":"node_state","ts":"2026-10-28T17:10:00Z","proxy_server_id":768,"machine_id":"e2865013c51398",`+
			`"level_max":2,"l1_seconds":40,"l2_seconds":20,"reasons":3,"sched_p99_us_max":180000,`+
			`"burst_est_s_min":-1,"burst_model":"uncalibrated","inflight_max":412,"admission_limit_min":24,`+
			`"waf_skipped_detect":5120,"waf_skipped_static":0,"waf_would_skip":0,`+
			`"shed_p0":0,"shed_p1":3,"shed_p2":88,"shed_p3":940,"would_shed":0,"gomaxprocs":1}`+"\n",
		nodeStateRowJSON(t, m))
}

func normalSample() nodeStateSample {
	return nodeStateSample{burstEstS: -1, burstModel: "uncalibrated", gomaxprocs: 1}
}

// B6: only completed minutes, only non-normal minutes or the heartbeat.
func TestNodeStateEmitRules(t *testing.T) {
	resetOverload(t)
	// 17:01 is not a heartbeat minute (17:00 and 17:10 are).
	m1 := time.Date(2026, 10, 28, 17, 1, 0, 0, time.UTC)
	for s := 0; s < 60; s++ {
		nodeStates.observe(m1.Add(time.Duration(s)*time.Second), normalSample())
	}
	require.Empty(t, nodeStates.drain(), "current minute never ships")

	m2 := m1.Add(time.Minute)
	nodeStates.observe(m2, normalSample())
	require.Empty(t, nodeStates.drain(), "a normal minute that is not a heartbeat ships nothing")

	hot := normalSample()
	hot.level, hot.reasons, hot.schedUs, hot.burstEstS, hot.burstModel = 1, reasonSched, 25000, 90, "calibrated"
	hot.inflight, hot.admissionLimit = 30, 12
	for s := 1; s < 60; s++ {
		x := hot
		if s == 30 {
			x.burstEstS, x.admissionLimit, x.inflight = 40, 9, 50
		}
		nodeStates.observe(m2.Add(time.Duration(s)*time.Second), x)
	}
	m3 := m2.Add(time.Minute)
	nodeStates.observe(m3, normalSample())
	rows := nodeStates.drain()
	require.Len(t, rows, 1)
	got := rows[0]
	require.Equal(t, uint32(m2.Unix()/60), got.ts)
	require.Equal(t, 1, got.levelMax)
	require.Equal(t, 59, got.l1Seconds)
	require.Equal(t, reasonSched, got.reasons)
	require.EqualValues(t, 25000, got.schedP99UsMax)
	require.EqualValues(t, 40, got.burstEstSMin)
	require.EqualValues(t, 9, got.admissionLimitMin)
	require.EqualValues(t, 50, got.inflightMax)
	require.Empty(t, nodeStates.drain(), "drained exactly once")

	// A counter alone makes a normal minute ship, with the minute's delta.
	overloadCounts.shed[3].Add(7)
	m4 := m3.Add(time.Minute)
	nodeStates.observe(m4, normalSample())
	rows = nodeStates.drain()
	require.Len(t, rows, 1)
	require.Equal(t, 0, rows[0].levelMax)
	require.EqualValues(t, 7, rows[0].counts[nsShedP3])

	// Heartbeat: a normal 17:10 ships.
	hb := time.Date(2026, 10, 28, 17, 10, 0, 0, time.UTC)
	nodeStates.observe(hb, normalSample())
	nodeStates.observe(hb.Add(time.Minute), normalSample())
	rows = nodeStates.drain()
	require.Len(t, rows, 1)
	require.Equal(t, uint32(hb.Unix()/60), rows[0].ts)
	require.Zero(t, rows[0].counts[nsShedP3], "counter deltas are per minute")
}

// B6: rows ride the stats batch, and two apps never both ship a minute.
func TestNodeStateRowsShipOnceAcrossApps(t *testing.T) {
	resetOverload(t)
	server, posts := captureServer(t, 200)
	defer server.Close()
	hb := time.Date(2026, 10, 28, 17, 20, 0, 0, time.UTC)
	nodeStates.observe(hb, normalSample())
	nodeStates.observe(hb.Add(time.Minute), normalSample())

	a1 := newTestApp(t, server.URL, "k", func(a *StatsApp) { a.machineID = "m1" })
	a2 := newTestApp(t, server.URL, "k", func(a *StatsApp) { a.machineID = "m1" })
	a1.flushOnce(0)
	a2.flushOnce(0)
	a1.flushBatch(0, true) // retired HTTP-only drains never take node_state

	var rows []map[string]any
	for _, p := range posts() {
		for _, row := range p.rows {
			if row["_type"] == "node_state" {
				rows = append(rows, row)
			}
		}
	}
	require.Len(t, rows, 1)
	require.Equal(t, "m1", rows[0]["machine_id"])
	require.Equal(t, "2026-10-28T17:20:00Z", rows[0]["ts"])
	require.Equal(t, float64(42), rows[0]["proxy_server_id"])
}

// The sampler feeds nothing while overload control is disabled.
func TestSamplerDisabledReportsNothing(t *testing.T) {
	resetOverload(t)
	hb := time.Date(2026, 10, 28, 17, 30, 0, 0, time.UTC)
	overload.sampler = samplerState{}
	overload.sampleOnce(hb, &fakeSignals{})
	overload.sampleOnce(hb.Add(time.Minute), &fakeSignals{})
	require.Empty(t, nodeStates.drain())

	setOverload(t, &OverloadConfig{WAF: "observe"}, 0)
	overload.sampler = samplerState{}
	overload.sampleOnce(hb, &fakeSignals{})
	overload.sampleOnce(hb.Add(time.Minute), &fakeSignals{})
	require.Len(t, nodeStates.drain(), 1, "the 17:30 heartbeat")
}
