package apxstats

import (
	"compress/gzip"
	"context"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const domainHealthVar = "apx_domain_health_key"

// Covers the fixed-width key, counter, map slot and owned fingerprint.
const domainHealthEntryBytes = 384

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
	shard := a.shards[key.VhostID&shardMask]
	if shard == nil {
		return
	}
	shard.mu.Lock()
	defer shard.mu.Unlock()

	counter := shard.domainHealth[key]
	if counter == nil {
		if !a.reserveDomainHealthKey() {
			metricDomainHealthOverflow.Inc()
			return
		}
		if a.memGov != nil && !a.memGov.tryReserve(domainHealthEntryBytes) {
			a.domainHealthKeys.Add(-1)
			metricDomainHealthOverflow.Inc()
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

func (a *StatsApp) drainDomainHealth() map[domainHealthKey]*domainHealthCounter {
	var snapshot map[domainHealthKey]*domainHealthCounter
	for _, shard := range a.shards {
		if shard == nil {
			continue
		}
		shard.mu.Lock()
		count := len(shard.domainHealth)
		if count > 0 {
			if snapshot == nil {
				snapshot = make(map[domainHealthKey]*domainHealthCounter)
			}
			for key, counter := range shard.domainHealth {
				snapshot[key] = counter
			}
			shard.domainHealth = nil
			a.domainHealthKeys.Add(-int64(count))
			if a.memGov != nil {
				a.memGov.release(count * domainHealthEntryBytes)
			}
		}
		shard.mu.Unlock()
	}
	return snapshot
}

func encodeDomainHealthRow(w *gzip.Writer, ps uint32, key domainHealthKey, counter *domainHealthCounter) error {
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
	_, err := w.Write([]byte(b.String()))
	return err
}
