package apxstats

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const defenseEvidenceHeader = "X-Apx-Defense-Evidence"
const defenseEvidenceSignature = "APX_DEFENSE_EVIDENCE/2"

type defenseEvidence struct {
	HTTP          bool     `json:"http"`
	CorazaAll     bool     `json:"coraza_all"`
	CorazaRuleIDs []uint32 `json:"coraza_rule_ids"`
}

func (e defenseEvidence) corazaExempt(id uint32) bool {
	if e.CorazaAll {
		return true
	}
	i := sort.Search(len(e.CorazaRuleIDs), func(i int) bool { return e.CorazaRuleIDs[i] >= id })
	return i < len(e.CorazaRuleIDs) && e.CorazaRuleIDs[i] == id
}

type defenseSnapshot struct {
	Evidence          defenseEvidence
	ObserveCoraza     bool
	SkipCorazaRuleIDs []uint32
}

func (s defenseSnapshot) copy() defenseSnapshot {
	s.Evidence.CorazaRuleIDs = append([]uint32{}, s.Evidence.CorazaRuleIDs...)
	s.SkipCorazaRuleIDs = append([]uint32{}, s.SkipCorazaRuleIDs...)
	return s
}

type defenseSnapshotKey struct{}
type defenseSnapshotHolder struct {
	mu       sync.RWMutex
	snapshot *defenseSnapshot
	privacy  *managedHeaderSnapshot
}

func (h *defenseSnapshotHolder) publish(s defenseSnapshot) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.snapshot != nil {
		return errors.New("Defense evidence already captured")
	}
	s = s.copy()
	h.snapshot = &s
	return nil
}
func (h *defenseSnapshotHolder) load() (defenseSnapshot, bool) {
	if h == nil {
		return defenseSnapshot{}, false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.snapshot == nil {
		return defenseSnapshot{}, false
	}
	return h.snapshot.copy(), true
}
func withDefenseSnapshotHolder(r *http.Request) (*http.Request, *defenseSnapshotHolder) {
	h := new(defenseSnapshotHolder)
	// Caddy's replacer is bound to this request pointer by PrepareRequest.
	*r = *r.WithContext(context.WithValue(r.Context(), defenseSnapshotKey{}, h))
	return r, h
}
func requestDefenseHolder(r *http.Request) *defenseSnapshotHolder {
	h, _ := r.Context().Value(defenseSnapshotKey{}).(*defenseSnapshotHolder)
	return h
}

// DefenseEvidenceHandler captures once, then restores only that snapshot at
// each WAF boundary. Headers and later vars are never an authority source.
type DefenseEvidenceHandler struct {
	ManagedHeaders     []managedHeaderCredential `json:"managed_headers,omitempty"`
	privacyNamesOnce   sync.Once
	privacyNames       []string
	Mode               string            `json:"mode"`
	HTTPVar            string            `json:"http_var,omitempty"`
	CorazaAllVar       string            `json:"coraza_all_var,omitempty"`
	CorazaRuleVars     map[string]string `json:"coraza_rule_vars,omitempty"`
	ObserveCorazaVar   string            `json:"observe_coraza_var,omitempty"`
	SkipCorazaRuleVars map[string]string `json:"skip_coraza_rule_vars,omitempty"`
}

func init() { caddy.RegisterModule(&DefenseEvidenceHandler{}) }
func (*DefenseEvidenceHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.apx_defense_evidence", New: func() caddy.Module { return new(DefenseEvidenceHandler) }}
}
func (h *DefenseEvidenceHandler) Validate() error {
	if h.Mode != "capture" && h.Mode != "capture_privacy" && h.Mode != "stamp_waf" {
		return errors.New("invalid Defense evidence mode")
	}
	if len(h.ManagedHeaders) > managedHeaderPairMaxCount || (h.Mode != "capture_privacy" && len(h.ManagedHeaders) > 0) {
		return errors.New("invalid managed Header privacy input")
	}
	for _, pair := range h.ManagedHeaders {
		if pair.Name == "" || len(pair.Name) > 128 || pair.Value == "" || len(pair.Value) > 1024 {
			return errors.New("invalid managed Header privacy input")
		}
	}
	if (h.Mode == "stamp_waf" || h.Mode == "capture_privacy") && (h.HTTPVar != "" || h.CorazaAllVar != "" || h.ObserveCorazaVar != "" || len(h.CorazaRuleVars) > 0 || len(h.SkipCorazaRuleVars) > 0) {
		return errors.New("stamp_waf cannot capture variables")
	}
	for _, vars := range []map[string]string{h.CorazaRuleVars, h.SkipCorazaRuleVars} {
		if len(vars) > len(defenseCRSIDs) {
			return errors.New("too many Defense selectors")
		}
		for key, name := range vars {
			id, err := strconv.ParseUint(key, 10, 32)
			if err != nil || strconv.FormatUint(id, 10) != key || !validDefenseCRSID(uint32(id)) || name == "" {
				return errors.New("invalid Defense selector")
			}
		}
	}
	h.privacyNamesOnce.Do(func() {
		seen := make(map[string]bool)
		for _, pair := range h.ManagedHeaders {
			name := strings.ToLower(pair.Name)
			if !seen[name] {
				seen[name] = true
				h.privacyNames = append(h.privacyNames, strings.Clone(name))
			}
		}
	})
	return nil
}
func strictDefenseVar(r *http.Request, name string) bool {
	if name == "" {
		return false
	}
	v, _ := caddyhttp.GetVar(r.Context(), name).(string)
	return v == "true"
}
func selectedDefenseVars(r *http.Request, vars map[string]string) []uint32 {
	ids := []uint32{}
	for key, name := range vars {
		if strictDefenseVar(r, name) {
			id, _ := strconv.ParseUint(key, 10, 32)
			ids = append(ids, uint32(id))
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
func clearDefenseMarkers(headers http.Header) {
	for name := range headers {
		lower := strings.ToLower(name)
		if lower == "x-apx-l7-header-exempt" || lower == "x-apx-defense-evidence" || lower == "x-apx-coraza-observe" || strings.HasPrefix(lower, "x-apx-coraza-skip-") {
			delete(headers, name)
		}
	}
}
func (h *DefenseEvidenceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.Mode != "capture_privacy" {
		clearDefenseMarkers(r.Header)
	}
	if h.Validate() != nil {
		return next.ServeHTTP(w, r)
	}
	holder := requestDefenseHolder(r)
	switch h.Mode {
	case "capture_privacy":
		if holder != nil {
			holder.mu.Lock()
			if holder.privacy == nil {
				holder.privacy = captureManagedHeaders(r.Header, h.privacyNames)
			}
			holder.mu.Unlock()
		}
	case "capture":
		if holder != nil {
			// Ignore later captures; only the first complete snapshot is authoritative.
			_ = holder.publish(defenseSnapshot{Evidence: defenseEvidence{HTTP: strictDefenseVar(r, h.HTTPVar), CorazaAll: strictDefenseVar(r, h.CorazaAllVar), CorazaRuleIDs: selectedDefenseVars(r, h.CorazaRuleVars)}, ObserveCoraza: strictDefenseVar(r, h.ObserveCorazaVar), SkipCorazaRuleIDs: selectedDefenseVars(r, h.SkipCorazaRuleVars)})
		}
	case "stamp_waf":
		if snapshot, ok := holder.load(); ok {
			if r.Header == nil {
				r.Header = make(http.Header)
			}
			marker, _ := json.Marshal(snapshot.Evidence)
			r.Header.Set(defenseEvidenceHeader, string(marker))
			if snapshot.ObserveCoraza {
				r.Header.Set("X-Apx-Coraza-Observe", "true")
			}
			for _, id := range snapshot.SkipCorazaRuleIDs {
				r.Header.Set("X-Apx-Coraza-Skip-"+strconv.FormatUint(uint64(id), 10), "true")
			}
		}
	}
	return next.ServeHTTP(w, r)
}

func defenseEvidenceFromHeaders(headers map[string][]string) (defenseEvidence, bool) {
	var marker string
	count := 0
	for name, values := range headers {
		if !strings.EqualFold(name, defenseEvidenceHeader) {
			continue
		}
		if count != 0 || len(values) != 1 {
			return defenseEvidence{}, false
		}
		count++
		marker = values[0]
	}
	// Each canonical CRS ID occupies at most six digits plus its comma.
	if count != 1 || len(marker) > 64+7*len(defenseCRSIDs) {
		return defenseEvidence{}, false
	}
	var evidence defenseEvidence
	if json.Unmarshal([]byte(marker), &evidence) != nil || evidence.CorazaRuleIDs == nil {
		return defenseEvidence{}, false
	}
	previous := uint32(0)
	for _, id := range evidence.CorazaRuleIDs {
		if id <= previous || !validDefenseCRSID(id) {
			return defenseEvidence{}, false
		}
		previous = id
	}
	canonical, err := json.Marshal(evidence)
	if err != nil || !bytes.Equal(canonical, []byte(marker)) {
		return defenseEvidence{}, false
	}
	return evidence, true
}
func validDefenseCRSID(id uint32) bool {
	i := sort.Search(len(defenseCRSIDs), func(i int) bool { return defenseCRSIDs[i] >= id })
	return i < len(defenseCRSIDs) && defenseCRSIDs[i] == id
}

var _ caddyhttp.MiddlewareHandler = (*DefenseEvidenceHandler)(nil)
var _ caddy.Validator = (*DefenseEvidenceHandler)(nil)

// Exact non-inline selector catalog from the control plane vendored CRS.
var defenseCRSIDs = []uint32{
	900000, 900001, 900010, 900100, 900110, 900115, 900120, 900130, 900200, 900220,
	900230, 900240, 900250, 900255, 900280, 900300, 900310, 900320, 900330, 900340,
	900350, 900400, 900500, 900950, 900990, 901001, 901100, 901110, 901111, 901115,
	901120, 901125, 901130, 901140, 901141, 901142, 901143, 901160, 901162, 901163,
	901164, 901165, 901167, 901168, 901169, 901170, 901171, 901200, 901320, 901340,
	901350, 901400, 901410, 901450, 901500, 905100, 905110, 911011, 911012, 911013,
	911014, 911015, 911016, 911017, 911018, 911100, 913011, 913012, 913013, 913014,
	913015, 913016, 913017, 913018, 913100, 920011, 920012, 920013, 920014, 920015,
	920016, 920017, 920018, 920100, 920120, 920121, 920160, 920170, 920171, 920180,
	920181, 920190, 920200, 920201, 920202, 920210, 920220, 920221, 920230, 920240,
	920250, 920260, 920270, 920271, 920272, 920273, 920274, 920275, 920280, 920290,
	920300, 920310, 920311, 920320, 920330, 920340, 920341, 920350, 920360, 920370,
	920380, 920390, 920400, 920410, 920420, 920430, 920440, 920450, 920451, 920460,
	920470, 920480, 920490, 920500, 920510, 920520, 920521, 920530, 920540, 920600,
	920610, 920620, 921011, 921012, 921013, 921014, 921015, 921016, 921017, 921018,
	921110, 921120, 921130, 921140, 921150, 921151, 921160, 921170, 921180, 921190,
	921200, 921210, 921220, 921230, 921240, 921421, 921422, 922100, 922110, 922120,
	922130, 930011, 930012, 930013, 930014, 930015, 930016, 930017, 930018, 930100,
	930110, 930120, 930121, 930130, 931011, 931012, 931013, 931014, 931015, 931016,
	931017, 931018, 931100, 931110, 931120, 931130, 931131, 932011, 932012, 932013,
	932014, 932015, 932016, 932017, 932018, 932120, 932125, 932130, 932131, 932140,
	932160, 932161, 932170, 932171, 932175, 932180, 932190, 932200, 932205, 932206,
	932210, 932220, 932230, 932231, 932232, 932235, 932236, 932237, 932238, 932239,
	932240, 932250, 932260, 932270, 932300, 932301, 932310, 932311, 932320, 932321,
	932330, 932331, 932370, 932380, 933011, 933012, 933013, 933014, 933015, 933016,
	933017, 933018, 933100, 933110, 933111, 933120, 933130, 933131, 933135, 933140,
	933150, 933151, 933160, 933161, 933170, 933180, 933190, 933200, 933210, 933211,
	934011, 934012, 934013, 934014, 934015, 934016, 934017, 934018, 934100, 934101,
	934110, 934120, 934130, 934140, 934150, 934160, 934170, 941010, 941011, 941012,
	941013, 941014, 941015, 941016, 941017, 941018, 941100, 941101, 941110, 941120,
	941130, 941140, 941150, 941160, 941170, 941180, 941181, 941190, 941200, 941210,
	941220, 941230, 941240, 941250, 941260, 941270, 941280, 941290, 941300, 941310,
	941320, 941330, 941340, 941350, 941360, 941370, 941380, 941390, 941400, 942011,
	942012, 942013, 942014, 942015, 942016, 942017, 942018, 942100, 942101, 942120,
	942130, 942131, 942140, 942150, 942151, 942152, 942160, 942170, 942180, 942190,
	942200, 942210, 942220, 942230, 942240, 942250, 942251, 942260, 942270, 942280,
	942290, 942300, 942310, 942320, 942321, 942330, 942340, 942350, 942360, 942361,
	942362, 942370, 942380, 942390, 942400, 942410, 942420, 942421, 942430, 942431,
	942432, 942440, 942441, 942442, 942450, 942460, 942470, 942480, 942490, 942500,
	942510, 942511, 942520, 942521, 942522, 942530, 942540, 942550, 942560, 943011,
	943012, 943013, 943014, 943015, 943016, 943017, 943018, 943100, 943110, 943120,
	944011, 944012, 944013, 944014, 944015, 944016, 944017, 944018, 944100, 944110,
	944120, 944130, 944140, 944150, 944151, 944152, 944200, 944210, 944240, 944250,
	944260, 944300, 949011, 949012, 949013, 949014, 949015, 949016, 949017, 949018,
	949052, 949053, 949054, 949055, 949059, 949060, 949061, 949062, 949063, 949110,
	949111, 949152, 949153, 949154, 949155, 949159, 949160, 949161, 949162, 949163,
	950010, 950011, 950012, 950013, 950014, 950015, 950016, 950017, 950018, 950021,
	950100, 950130, 950140, 951010, 951011, 951012, 951013, 951014, 951015, 951016,
	951017, 951018, 951100, 951110, 951120, 951130, 951140, 951150, 951160, 951170,
	951180, 951190, 951200, 951210, 951220, 951230, 951240, 951250, 951260, 952010,
	952011, 952012, 952013, 952014, 952015, 952016, 952017, 952018, 952100, 952110,
	953010, 953011, 953012, 953013, 953014, 953015, 953016, 953017, 953018, 953100,
	953101, 953110, 953120, 954010, 954011, 954012, 954013, 954014, 954015, 954016,
	954017, 954018, 954100, 954110, 954120, 954130, 955010, 955011, 955012, 955013,
	955014, 955015, 955016, 955017, 955018, 955100, 955110, 955120, 955130, 955140,
	955150, 955160, 955170, 955180, 955190, 955200, 955210, 955220, 955230, 955240,
	955250, 955260, 955270, 955280, 955290, 955300, 955310, 955320, 955330, 955340,
	955350, 959011, 959012, 959013, 959014, 959015, 959016, 959017, 959018, 959052,
	959053, 959054, 959055, 959059, 959060, 959061, 959062, 959063, 959100, 959101,
	959152, 959153, 959154, 959155, 959159, 959160, 959161, 959162, 959163, 980011,
	980012, 980013, 980014, 980015, 980016, 980017, 980018, 980041, 980042, 980043,
	980044, 980045, 980046, 980047, 980048, 980049, 980050, 980051, 980099, 980170,
}
