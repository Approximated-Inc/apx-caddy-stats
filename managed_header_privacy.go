package apxstats

import (
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

const managedHeaderPrivacySignature = "APX_MANAGED_HEADER_PRIVACY/1"
const managedHeaderWorkMaxBytes = 1 << 20
const managedHeaderPairMaxCount = 128 * 16 * 16

type managedHeaderCredential struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// The private state keeps a generation-owned immutable name reference and a
// monotonic privacy flag. Later Header names can only reduce text detail; they
// never change the separately frozen exemption/evidence authority.
type managedHeaderSnapshot struct {
	mu      sync.Mutex
	maskAll bool
	names   []string
	work    int
}

func captureManagedHeaders(headers http.Header, names []string) *managedHeaderSnapshot {
	snapshot := &managedHeaderSnapshot{names: names}
	snapshot.captureNames(headers)
	return snapshot
}

func (s *managedHeaderSnapshot) captureNames(headers http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maskAll {
		return
	}
	for _, name := range s.names {
		for supplied := range headers {
			s.work += len(name) + len(supplied)
			if s.work > managedHeaderWorkMaxBytes || strings.EqualFold(name, supplied) {
				s.maskAll = true
				return
			}
		}
	}
}

func (s *managedHeaderSnapshot) redact(text string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maskAll {
		return ""
	}
	return text
}

type managedHeaderRegistryEntry struct {
	snapshot *managedHeaderSnapshot
	refs     int
	poisoned bool
}

type managedHeaderRegistry struct {
	mu         sync.RWMutex
	entries    map[string]*managedHeaderRegistryEntry
	maxEntries int
}

func newManagedHeaderRegistry(entries int) *managedHeaderRegistry {
	return &managedHeaderRegistry{entries: make(map[string]*managedHeaderRegistryEntry), maxEntries: entries}
}

var corazaPrivacyRegistry = newManagedHeaderRegistry(4096)

// CorazaPrivacyBridge is a private in-process interface discovered by the WAF
// module. It transports no values or hashes through headers or evidence proof.
type CorazaPrivacyBridge struct{ registry *managedHeaderRegistry }

func init() { caddy.RegisterModule(CorazaPrivacyBridge{}) }
func (CorazaPrivacyBridge) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "apx.coraza_privacy", New: func() caddy.Module { return new(CorazaPrivacyBridge) }}
}
func (b *CorazaPrivacyBridge) state() *managedHeaderRegistry {
	if b.registry != nil {
		return b.registry
	}
	return corazaPrivacyRegistry
}
func (b *CorazaPrivacyBridge) Bind(id string, r *http.Request) func() {
	registry := b.state()
	snapshot := &managedHeaderSnapshot{maskAll: true}
	if holder := requestDefenseHolder(r); holder != nil {
		holder.mu.RLock()
		if holder.privacy != nil {
			snapshot = holder.privacy
		}
		holder.mu.RUnlock()
	}
	snapshot.captureNames(r.Header)
	registry.mu.Lock()
	if previous := registry.entries[id]; previous != nil {
		previous.poisoned = true
		previous.refs++
		registry.mu.Unlock()
		return registry.release(id, previous)
	}
	if id == "" || len(id) > 128 || len(registry.entries) >= registry.maxEntries {
		registry.mu.Unlock()
		return func() {}
	}
	entry := &managedHeaderRegistryEntry{snapshot: snapshot, refs: 1}
	registry.entries[id] = entry
	registry.mu.Unlock()
	return registry.release(id, entry)
}
func (registry *managedHeaderRegistry) release(id string, entry *managedHeaderRegistryEntry) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			registry.mu.Lock()
			entry.refs--
			if entry.refs == 0 && registry.entries[id] == entry {
				delete(registry.entries, id)
			}
			registry.mu.Unlock()
		})
	}
}
func (b *CorazaPrivacyBridge) Redact(id, text string) string {
	registry := b.state()
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	if snapshot := registry.entries[id]; snapshot != nil {
		if snapshot.poisoned {
			return ""
		}
		return snapshot.snapshot.redact(text)
	}
	return ""
}

// Only the exact supported privacy proof permits captured-value redaction.
// Unknown versions conservatively mask complete text without affecting evidence.
func corazaTransactionManagedPrivacyVersion(tx corazaTxView) int {
	version := 0
	if producer := tx.Producer(); producer != nil {
		for _, component := range producer.Rulesets() {
			if !strings.HasPrefix(component, "APX_MANAGED_HEADER_PRIVACY/") {
				continue
			}
			if component != managedHeaderPrivacySignature {
				return -1
			}
			version = 1
		}
	}
	return version
}
