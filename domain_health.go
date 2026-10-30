package apxstats

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const domainHealthVar = "apx_domain_health_key"

// Covers the fixed-width key, counter, map slot and owned fingerprint.
const domainHealthEntryBytes = 384

// Caddy sets this duration only after RoundTrip returns an actual response.
// Snapshot it before the route so preexisting response placeholders are not
// evidence that this request obtained another upstream response.
type domainHealthResponseSnapshot struct {
	latency time.Duration
	known   bool
}

func snapshotDomainHealthResponse(r *http.Request) domainHealthResponseSnapshot {
	repl, _ := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if repl == nil {
		return domainHealthResponseSnapshot{}
	}
	value, _ := repl.Get("http.reverse_proxy.upstream.latency")
	latency, known := value.(time.Duration)
	return domainHealthResponseSnapshot{latency, known}
}

func domainHealthUpstreamStatus(r *http.Request, w *recorder, servErr error, origin string, before domainHealthResponseSnapshot) (int, bool) {
	if r.Context().Err() != nil || origin != OriginUpstream {
		return 0, false
	}
	// Caddy swallows context.Canceled while waiting for headers, leaving a
	// selected upstream and nil handler error without writing any response.
	// Earlier retry responses also leave placeholders behind. Neither case
	// proves completion of the final attempt. A terminal response-retry error
	// is the explicit exception: Caddy received the final response but chose
	// not to copy it to the client.
	if !w.wrote && !retriedUpstreamResponse(servErr) {
		return 0, false
	}
	response := snapshotDomainHealthResponse(r)
	if !response.known || response.latency <= 0 || (before.known && response.latency == before.latency) {
		return 0, false
	}
	repl, _ := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	value, _ := repl.Get("http.reverse_proxy.status_code")
	status, ok := value.(int)
	// This is the original upstream status, set before handle_response can
	// rewrite it. A hijacked 101 must not inherit the recorder's default 200.
	return status, ok && (status == http.StatusSwitchingProtocols || status >= 200 && status <= 599)
}

type domainHealthKey struct {
	TsUnixMin        uint32
	VhostID          uint32
	ConfigurationKey string
}

type domainHealthCounter struct {
	RequestCount      uint64
	RoutingResponses  uint64
	UpstreamResponses uint64
	UpstreamSuccesses uint64
	Upstream5xx       uint64
	ProxyErrors       uint64
}

// A route's server-side vars are read after it handled the request. Header
// values and arbitrary request-replacer input are deliberately not proof.
func domainHealthConfigurationKey(ctx context.Context) string {
	vars, _ := ctx.Value(caddyhttp.VarsCtxKey).(map[string]any)
	key, _ := vars[domainHealthVar].(string)
	if !validDomainHealthKey(key) {
		return ""
	}
	return key
}

func validDomainHealthKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	for i := 0; i < len(key); i++ {
		if !(key[i] >= '0' && key[i] <= '9') && !(key[i] >= 'a' && key[i] <= 'f') {
			return false
		}
	}
	return true
}

func (a *StatsApp) RecordDomainHealth(key domainHealthKey, delta domainHealthCounter) {
	if key.VhostID == 0 || !validDomainHealthKey(key.ConfigurationKey) || a.cfg.maxBuffer <= 0 {
		return
	}
	if a.domainHealthRetired.Load() {
		countDomainHealthDrop(domainHealthDropRetired, 1)
		return
	}
	shard := a.shards[key.VhostID&shardMask]
	if shard == nil {
		return
	}
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if a.domainHealthRetired.Load() {
		countDomainHealthDrop(domainHealthDropRetired, 1)
		return
	}

	counter := shard.domainHealth[key]
	if counter == nil {
		if !a.reserveDomainHealthKey() {
			metricDomainHealthOverflow.Inc()
			countDomainHealthDrop(domainHealthDropCapacity, 1)
			return
		}
		if !reserveDomainHealthCredit() {
			a.domainHealthKeys.Add(-1)
			metricDomainHealthOverflow.Inc()
			countDomainHealthDrop(domainHealthDropCapacity, 1)
			return
		}
		if a.memGov != nil && !a.memGov.tryReserve(domainHealthEntryBytes) {
			a.domainHealthKeys.Add(-1)
			domainHealthCredits.Add(-1)
			metricDomainHealthOverflow.Inc()
			countDomainHealthDrop(domainHealthDropPressure, 1)
			return
		}
		if shard.domainHealth == nil {
			shard.domainHealth = make(map[domainHealthKey]*domainHealthCounter)
		}
		key.ConfigurationKey = strings.Clone(key.ConfigurationKey)
		counter = &domainHealthCounter{}
		shard.domainHealth[key] = counter
	}
	counter.RequestCount += delta.RequestCount
	counter.RoutingResponses += delta.RoutingResponses
	counter.UpstreamResponses += delta.UpstreamResponses
	counter.UpstreamSuccesses += delta.UpstreamSuccesses
	counter.Upstream5xx += delta.Upstream5xx
	counter.ProxyErrors += delta.ProxyErrors
}

func (a *StatsApp) reserveDomainHealthKey() bool {
	for {
		count := a.domainHealthKeys.Load()
		if count >= int64(a.cfg.maxBuffer) {
			return false
		}
		if a.domainHealthKeys.CompareAndSwap(count, count+1) {
			return true
		}
	}
}

func (a *StatsApp) detachDomainHealth() ([shardCount]map[domainHealthKey]*domainHealthCounter, int) {
	var detached [shardCount]map[domainHealthKey]*domainHealthCounter
	total := 0
	for i, shard := range a.shards {
		if shard == nil {
			continue
		}
		shard.mu.Lock()
		count := len(shard.domainHealth)
		if count > 0 {
			detached[i] = shard.domainHealth
			total += count
			shard.domainHealth = nil
			a.domainHealthKeys.Add(-int64(count))
			if a.memGov != nil {
				a.memGov.release(count * domainHealthEntryBytes)
			}
		}
		shard.mu.Unlock()
	}
	return detached, total
}

func (a *StatsApp) drainDomainHealth() *domainHealthSnapshot {
	detached, total := a.detachDomainHealth()
	if total == 0 {
		return nil
	}
	snapshot := make(map[domainHealthKey]*domainHealthCounter, total)
	for _, rows := range detached {
		for key, counter := range rows {
			snapshot[key] = counter
		}
	}
	return &domainHealthSnapshot{rows: snapshot, lease: &domainHealthLease{records: int64(total)}}
}

func encodeDomainHealthRow(w io.Writer, ps uint32, key domainHealthKey, counter *domainHealthCounter) error {
	var b strings.Builder
	b.Grow(360)
	b.WriteByte('{')
	writeString(&b, "_type", "domain_health")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(key.TsUnixMin))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeUint32(&b, "vhost_id", key.VhostID)
	b.WriteByte(',')
	writeString(&b, "configuration_key", key.ConfigurationKey)
	b.WriteByte(',')
	writeUint64(&b, "request_count", counter.RequestCount)
	b.WriteByte(',')
	writeUint64(&b, "routing_responses", counter.RoutingResponses)
	b.WriteByte(',')
	writeUint64(&b, "upstream_responses", counter.UpstreamResponses)
	b.WriteByte(',')
	writeUint64(&b, "upstream_successes", counter.UpstreamSuccesses)
	b.WriteByte(',')
	writeUint64(&b, "upstream_5xx", counter.Upstream5xx)
	b.WriteByte(',')
	writeUint64(&b, "proxy_errors", counter.ProxyErrors)
	b.WriteString("}\n")
	_, err := io.WriteString(w, b.String())
	return err
}
