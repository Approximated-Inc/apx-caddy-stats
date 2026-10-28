package apxstats

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	defaultStopWaitMs         = 2_000
	defaultShutdownDeadlineMs = 30_000
	// shipQueueCap bounds encoded bodies waiting for shipLoop. A full queue
	// drops the oldest: fresher data is worth more to live signals.
	shipQueueCap = 2
)

func (c ingestRuntime) stopWaitOrDefault() time.Duration {
	if c.stopWait > 0 {
		return c.stopWait
	}
	return defaultStopWaitMs * time.Millisecond
}

func (c ingestRuntime) shutdownDeadlineOrDefault() time.Duration {
	if c.shutdownDeadline > 0 {
		return c.shutdownDeadline
	}
	return defaultShutdownDeadlineMs * time.Millisecond
}

// shipJob is one encoded batch waiting to ship.
type shipJob struct {
	body     []byte
	rows     int
	retries  int
	shutdown bool // ship under the shutdown deadline and a retired slot
}

// shipQueue is a small FIFO with drop-oldest overflow. One consumer
// (shipLoop); producers are flushLoop and shipLoop's own requeue.
type shipQueue struct {
	mu     sync.Mutex
	jobs   []*shipJob
	closed bool
	notify chan struct{}
}

func newShipQueue() *shipQueue {
	return &shipQueue{notify: make(chan struct{}, 1)}
}

func (q *shipQueue) signal() {
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// push appends j, returning the job dropped to make room (nil if none).
func (q *shipQueue) push(j *shipJob) (dropped *shipJob) {
	q.mu.Lock()
	if len(q.jobs) >= shipQueueCap {
		dropped = q.jobs[0]
		q.jobs = q.jobs[1:]
	}
	q.jobs = append(q.jobs, j)
	q.mu.Unlock()
	q.signal()
	return dropped
}

// pushFront requeues a job cut short by Stop, ahead of everything else.
// Allowed after close: only the consumer calls it.
func (q *shipQueue) pushFront(j *shipJob) {
	q.mu.Lock()
	q.jobs = append([]*shipJob{j}, q.jobs...)
	q.mu.Unlock()
	q.signal()
}

func (q *shipQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.signal()
}

// pop blocks for the next job. ok is false once closed and empty.
func (q *shipQueue) pop() (*shipJob, bool) {
	for {
		q.mu.Lock()
		if len(q.jobs) > 0 {
			j := q.jobs[0]
			q.jobs = q.jobs[1:]
			q.mu.Unlock()
			return j, true
		}
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return nil, false
		}
		<-q.notify
	}
}

// retiredShipSlots bounds shipping by stopping/retired generations
// process-wide. With reloads every few seconds against a hung ingest this
// caps live goroutines and retained bodies at its capacity.
var retiredShipSlots = make(chan struct{}, 2)

func acquireRetiredSlot() bool {
	select {
	case retiredShipSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseRetiredSlot() { <-retiredShipSlots }

// shipFailureResult labels a failed shutdown-phase or retired ship.
func shipFailureResult(ctx context.Context, err error) string {
	switch {
	case ctx.Err() != nil:
		return "deadline"
	case isPermanent(err):
		return "permanent"
	default:
		return "exhausted"
	}
}

// startShipper builds the queue and contexts and starts shipLoop. shipLoop
// is deliberately not in a.wg: Stop waits for it only up to stopWait.
func (a *StatsApp) startShipper() {
	a.shipQ = newShipQueue()
	a.shipDone = make(chan struct{})
	a.shutdownReady = make(chan struct{})
	a.tickCtx, a.tickCancel = context.WithCancel(context.Background())
	go a.shipLoop()
}

// beginShutdownShipping starts the shutdown deadline. Called by flushLoop
// once, on stop, after cancelling the tick context.
func (a *StatsApp) beginShutdownShipping() {
	a.shutdownCtx, a.shutdownCancel = context.WithTimeout(context.Background(), a.cfg.shutdownDeadlineOrDefault())
	close(a.shutdownReady)
}

func (a *StatsApp) enqueueShip(j *shipJob) {
	if dropped := a.shipQ.push(j); dropped != nil {
		atomic.AddUint64(&a.dropped, uint64(dropped.rows))
		metricDroppedRows.Add(float64(dropped.rows))
		metricShipQueueDroppedRows.Add(float64(dropped.rows))
		if a.logger != nil {
			a.logger.Warn("apx_stats: ship queue full; dropping oldest batch",
				zap.Int("rows", dropped.rows))
		}
	}
}

// awaitShipper waits for shipLoop to finish, at most stopWait. A healthy
// ingest (50–300 ms POST) finishes inside the wait, so graceful shutdown
// keeps today's no-loss behaviour; a hung one keeps going in the
// background under the shutdown deadline.
func (a *StatsApp) awaitShipper() {
	if a.shipDone == nil {
		return
	}
	start := time.Now()
	t := time.NewTimer(a.cfg.stopWaitOrDefault())
	defer t.Stop()
	select {
	case <-a.shipDone:
	case <-t.C:
		if a.logger != nil {
			a.logger.Warn("apx_stats: stop returned before the final batch shipped; continuing in the background",
				zap.Duration("stop_wait", a.cfg.stopWaitOrDefault()))
		}
	}
	metricStopWait.Observe(time.Since(start).Seconds())
}

func (a *StatsApp) shipLoop() {
	var slot bool
	defer func() {
		if slot {
			releaseRetiredSlot()
		}
		if a.shutdownCancel != nil {
			a.shutdownCancel()
		}
		close(a.shipDone)
	}()
	for {
		j, ok := a.shipQ.pop()
		if !ok {
			return
		}
		ctx := a.tickCtx
		if j.shutdown || a.tickCtx.Err() != nil {
			<-a.shutdownReady
			ctx = a.shutdownCtx
			if !j.shutdown {
				j.shutdown = true
				j.retries = a.cfg.shutdownMaxRetries
			}
			if !slot {
				if !acquireRetiredSlot() {
					a.dropRows(j.rows, "busy", nil)
					a.dropQueued("busy")
					return
				}
				slot = true
			}
		}
		err := a.shipWithRetryN(ctx, j.body, j.retries)
		switch {
		case err == nil:
			if j.shutdown {
				metricRetiredShip.WithLabelValues("ok").Inc()
			}
		case !j.shutdown && a.tickCtx.Err() != nil:
			// Cut short by Stop: put the body back at the head and retry it
			// under the shutdown deadline instead of dropping it.
			a.shipQ.pushFront(j)
		case j.shutdown:
			a.dropRows(j.rows, shipFailureResult(ctx, err), err)
		default:
			a.dropRows(j.rows, "", err)
		}
	}
}

// dropQueued counts every job still queued as dropped.
func (a *StatsApp) dropQueued(result string) {
	for {
		j, ok := a.shipQ.pop()
		if !ok {
			return
		}
		a.dropRows(j.rows, result, nil)
	}
}
