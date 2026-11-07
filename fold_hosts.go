package apxstats

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// maxFoldHostBytes is the longest DNS name. Longer Hosts are not looked up.
const maxFoldHostBytes = 253

var metricFoldHostEntries = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "apx_stats_fold_host_entries",
	Help: "Entries in the fold_hosts table of the app that started last",
})

var metricFoldHostsDropped = promauto.NewCounter(prometheus.CounterOpts{
	Name: "apx_stats_fold_hosts_dropped_total",
	Help: "fold_hosts entries ignored at provision because the host or id was not canonical",
})

var metricFoldHostVarConflicts = promauto.NewCounter(prometheus.CounterOpts{
	Name: "apx_stats_fold_host_var_conflicts_total",
	Help: "Requests whose vhost_id var named a different vhost than the fold_hosts table, which won",
})

// provisionFoldHosts drops entries that could never match instead of failing,
// because a refused config would freeze the cluster on its last good one.
func (a *StatsApp) provisionFoldHosts() {
	for host, id := range a.FoldHosts {
		if id == 0 || !isCanonicalFoldHost(host) {
			delete(a.FoldHosts, host)
			metricFoldHostsDropped.Inc()
			if a.logger != nil {
				a.logger.Warn("apx_stats: ignored fold_hosts entry", zap.String("host", host), zap.Uint32("vhost_id", id))
			}
		}
	}
}

// FoldHostTable returns the loaded table. It is read-only after Provision.
func (a *StatsApp) FoldHostTable() map[string]uint32 { return a.FoldHosts }

// isCanonicalFoldHost reports whether a table key is a form lookups can produce.
func isCanonicalFoldHost(host string) bool {
	if host == "" || len(host) > maxFoldHostBytes || host[len(host)-1] == '.' {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

// lookupFoldHost resolves a request's Host: the port and one trailing dot go,
// and ASCII case folds. An IP literal in brackets misses at the port check, and
// a non-ASCII name misses because no key holds one. It does not allocate.
func lookupFoldHost(table map[string]uint32, raw string) (uint32, bool) {
	if len(table) == 0 {
		return 0, false
	}
	host := raw
	if i := strings.IndexByte(host, ':'); i >= 0 {
		if !isPort(host[i+1:]) {
			return 0, false
		}
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > maxFoldHostBytes {
		return 0, false
	}
	var buf [maxFoldHostBytes]byte
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	id, ok := table[string(buf[:len(host)])]
	return id, ok
}

func isPort(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
