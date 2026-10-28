package apxstats

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
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
		dropped = q.shiftLocked()
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

// shiftLocked removes the head in place and clears the vacated slot, so a
// retired generation's queue never pins bodies it already shipped.
func (q *shipQueue) shiftLocked() *shipJob {
	j := q.jobs[0]
	n := copy(q.jobs, q.jobs[1:])
	q.jobs[n] = nil
	q.jobs = q.jobs[:n]
	return j
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
			j := q.shiftLocked()
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
	a.attemptCtx, a.attemptCancel = context.WithCancel(context.Background())
	go a.shipLoop()
}

// beginShutdownShipping starts the shutdown deadline. Called by flushLoop
// once, on stop, after cancelling the tick context. A tick attempt still in
// flight is cut only when the deadline expires.
func (a *StatsApp) beginShutdownShipping() {
	a.shutdownCtx, a.shutdownCancel = context.WithTimeout(context.Background(), a.cfg.shutdownDeadlineOrDefault())
	context.AfterFunc(a.shutdownCtx, a.attemptCancel)
	close(a.shutdownReady)
}

// processExiting reports whether Caddy is exiting the process (it then
// os.Exits right after stopping apps). A variable so tests can set it.
var processExiting = caddy.Exiting

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

// awaitShipper waits for the final drain, encode and ship (shipDone closes
// only after flushLoop closed the queue), at most stopWait from start. A
// healthy ingest (50–300 ms POST) finishes inside the wait, so graceful
// shutdown keeps today's no-loss behaviour; a hung one keeps going in the
// background under the shutdown deadline. On process exit nothing runs
// after Stop, so it waits up to the shutdown deadline instead.
func (a *StatsApp) awaitShipper(start time.Time) {
	if a.shipDone == nil {
		a.wg.Wait()
		return
	}
	wait := a.cfg.stopWaitOrDefault()
	if processExiting() {
		wait = a.cfg.shutdownDeadlineOrDefault()
	}
	t := time.NewTimer(wait - time.Since(start))
	defer t.Stop()
	select {
	case <-a.shipDone:
	case <-t.C:
		if a.logger != nil {
			a.logger.Warn("apx_stats: stop returned before the final batch shipped; continuing in the background",
				zap.Duration("wait", wait))
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
		ctx, wait := a.attemptCtx, a.tickCtx
		if j.shutdown || a.tickCtx.Err() != nil {
			<-a.shutdownReady
			ctx, wait = a.shutdownCtx, a.shutdownCtx
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
		err := a.shipWithRetryWait(ctx, wait, j.body, j.retries)
		switch {
		case err == nil:
			if j.shutdown {
				metricRetiredShip.WithLabelValues("ok").Inc()
			}
		case !j.shutdown && !isPermanent(err) && a.tickCtx.Err() != nil:
			// Retries ended by Stop: put the body back at the head and retry
			// it under the shutdown deadline instead of dropping it.
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
