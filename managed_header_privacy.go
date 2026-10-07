package apxstats

import (
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

const managedHeaderPrivacySignature = "APX_MANAGED_HEADER_PRIVACY/1"
const managedHeaderWorkMaxBytes = 1 << 20
const managedHeaderValueMaxCount = 128
const managedHeaderValueMaxBytes = 64 << 10
const managedHeaderPairMaxCount = 128 * 16 * 16

type managedHeaderCredential struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type managedHeaderSnapshot struct {
	values  []string
	maskAll bool
	bytes   int
	budget  *managedHeaderRedactionBudget
}

type managedHeaderRedactionBudget struct {
	mu      sync.Mutex
	work    int
	maskAll bool
}

func captureManagedHeaders(headers http.Header, pairs []managedHeaderCredential) managedHeaderSnapshot {
	snapshot := managedHeaderSnapshot{budget: &managedHeaderRedactionBudget{}}
	seen := make(map[string]bool)
	work := 0
	for _, pair := range pairs {
		for name, fields := range headers {
			work += len(name) + len(pair.Name)
			if work > managedHeaderWorkMaxBytes {
				return managedHeaderSnapshot{maskAll: true}
			}
			if !strings.EqualFold(name, pair.Name) {
				continue
			}
			for _, field := range fields {
				work += len(field) + len(pair.Value)
				if work > managedHeaderWorkMaxBytes {
					return managedHeaderSnapshot{maskAll: true}
				}
				if !strings.Contains(field, pair.Value) || seen[pair.Value] {
					continue
				}
				if len(snapshot.values) == managedHeaderValueMaxCount || snapshot.bytes+len(pair.Value) > managedHeaderValueMaxBytes {
					return managedHeaderSnapshot{maskAll: true}
				}
				seen[pair.Value] = true
				snapshot.values = append(snapshot.values, strings.Clone(pair.Value))
				snapshot.bytes += len(pair.Value)
			}
		}
	}
	return snapshot
}

func (s managedHeaderSnapshot) redact(text string) string {
	if s.maskAll {
		return ""
	}
	if s.budget == nil {
		return ""
	}
	s.budget.mu.Lock()
	defer s.budget.mu.Unlock()
	if s.budget.maskAll {
		return ""
	}
	for _, value := range s.values {
		s.budget.work += len(text) + len(value)
		if s.budget.work > managedHeaderWorkMaxBytes {
			s.budget.maskAll = true
			return ""
		}
		if strings.Contains(text, value) {
			for _, credential := range s.values {
				if strings.Contains("[REDACTED]", credential) {
					return ""
				}
			}
			return "[REDACTED]"
		}
	}
	return text
}

type managedHeaderRegistryEntry struct {
	snapshot managedHeaderSnapshot
	refs     int
}

type managedHeaderRegistry struct {
	mu                             sync.RWMutex
	entries                        map[string]*managedHeaderRegistryEntry
	slots, bytes                   int
	maxEntries, maxSlots, maxBytes int
}

func newManagedHeaderRegistry(entries, slots, bytes int) *managedHeaderRegistry {
	return &managedHeaderRegistry{entries: make(map[string]*managedHeaderRegistryEntry), maxEntries: entries, maxSlots: slots, maxBytes: bytes}
}

var corazaPrivacyRegistry = newManagedHeaderRegistry(4096, 16384, 8<<20)

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
	snapshot := managedHeaderSnapshot{maskAll: true}
	if holder := requestDefenseHolder(r); holder != nil {
		holder.mu.RLock()
		if holder.privacy != nil {
			snapshot = *holder.privacy
		}
		holder.mu.RUnlock()
	}
	registry.mu.Lock()
	if previous := registry.entries[id]; previous != nil {
		previous.snapshot.maskAll = true
		previous.refs++
		registry.mu.Unlock()
		return registry.release(id, previous)
	}
	if id == "" || len(id) > 128 || len(registry.entries) >= registry.maxEntries || registry.slots+len(snapshot.values) > registry.maxSlots || registry.bytes+snapshot.bytes > registry.maxBytes {
		registry.mu.Unlock()
		return func() {}
	}
	entry := &managedHeaderRegistryEntry{snapshot: snapshot, refs: 1}
	registry.entries[id] = entry
	registry.slots += len(snapshot.values)
	registry.bytes += snapshot.bytes
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
				registry.slots -= len(entry.snapshot.values)
				registry.bytes -= entry.snapshot.bytes
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
