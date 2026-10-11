package apxstats

import (
	"fmt"
	"hash/maphash"
	"html"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
)

const managedHeaderPrivacySignature = "APX_MANAGED_HEADER_PRIVACY/1"
const managedHeaderPairMaxCount = 128 * 16 * 16
const managedHeaderNameMaxBytes = 128
const managedHeaderValueMaxBytes = 1024

// managedHeaderMaskedText replaces telemetry text that held a managed Header
// value, so a masked field is distinguishable from an absent (empty) one.
const managedHeaderMaskedText = "[masked: managed header value]"

// managedHeaderMaskedURLPart replaces a URL path segment, query parameter or
// query that held a managed value, keeping the URL's shape.
const managedHeaderMaskedURLPart = "[masked]"

// managedHeaderMaskedIP replaces a managed forwarded IP. 100:: is the RFC 6666
// discard-only prefix: never a client, and distinct from "::" (absent).
const managedHeaderMaskedIP = "100::"

// A managed value at least this long also masks any WAF text containing it.
// Shorter values ("1", "true") occur inside unrelated text everywhere, so they
// are only matched as whole Header field values.
const managedHeaderContainMinBytes = 8

type managedHeaderCredential struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Format keeps managed values out of %v, %+v, %#v and %s output.
func (c managedHeaderCredential) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "{"+c.Name+" [redacted]}")
}

// managedHeaderPolicy is compiled once per capture_privacy handler and never
// mutated. A Header field carries a managed value when the field, or one of
// its comma-separated elements, equals one after trimming and ASCII case
// folding (an IP in any textual form), directly or after the URL and HTML
// decoding CRS applies to request Headers.
type managedHeaderPolicy struct {
	names     map[string]struct{} // ASCII-lowercase managed Header names
	nameLens  [managedHeaderNameMaxBytes + 1]bool
	values    map[string]struct{} // ASCII-lowercase managed values
	valueLens [managedHeaderValueMaxBytes + 1]bool
	lengths   []int                   // the set lengths of valueLens below managedHeaderContainMinBytes, ascending
	ips       map[netip.Addr]struct{} // IPs among the values and their list elements
	contain   foldMatcher             // values of at least managedHeaderContainMinBytes
	question  bool                    // a value holds a literal '?', which can split it across a URL's path and query
	// Values shorter than managedHeaderContainMinBytes holding a '+', with
	// each '+' as a space (CRS urlDecodeUni), matched only as URL tokens.
	plusTokens map[string]struct{}
	// Values of at least managedHeaderContainMinBytes managed under names other
	// than User-Agent. A User-Agent value only masks a whole User-Agent: a rule
	// on a common prefix ("Mozilla/5.0") must not blank every browser's.
	containInUserAgent foldMatcher
	// The markers this policy writes in place of masked text, URL parts and
	// IPs; never themselves a managed value.
	maskedText, maskedURLPart, maskedIP string
}

func (*managedHeaderPolicy) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "managedHeaderPolicy{redacted}")
}

// compileManagedHeaderPolicy expects pairs already validated by the handler.
func compileManagedHeaderPolicy(pairs []managedHeaderCredential) *managedHeaderPolicy {
	p := &managedHeaderPolicy{names: map[string]struct{}{}, values: map[string]struct{}{}, ips: map[netip.Addr]struct{}{}}
	inUserAgent := map[string]bool{}
	for _, pair := range pairs {
		name := foldASCII(pair.Name)
		p.names[name] = struct{}{}
		p.nameLens[len(name)] = true
		value := foldASCII(pair.Value)
		if name != "user-agent" && len(value) >= managedHeaderContainMinBytes && !inUserAgent[value] {
			inUserAgent[value] = true
			p.containInUserAgent.add(value)
		}
		if _, seen := p.values[value]; seen {
			continue
		}
		p.values[value] = struct{}{}
		p.valueLens[len(value)] = true
		p.question = p.question || strings.IndexByte(value, '?') >= 0
		// CRS urlDecodeUni (and form decoding) turn a literal '+' into a space.
		if strings.IndexByte(value, '+') >= 0 {
			if spaced := strings.ReplaceAll(value, "+", " "); len(value) >= managedHeaderContainMinBytes {
				p.contain.add(spaced)
			} else {
				if p.plusTokens == nil {
					p.plusTokens = map[string]struct{}{}
				}
				p.plusTokens[spaced] = struct{}{}
			}
		}
		if len(value) >= managedHeaderContainMinBytes {
			p.contain.add(value)
		}
		for _, element := range strings.Split(pair.Value, ",") {
			if ip, err := netip.ParseAddr(trimSpace(element)); err == nil {
				p.ips[ip.Unmap()] = struct{}{}
			}
		}
	}
	// Values of managedHeaderContainMinBytes or more are found by contain
	// anywhere, so only shorter ones need the whole-token scan.
	for n, set := range p.valueLens[:managedHeaderContainMinBytes] {
		if set {
			p.lengths = append(p.lengths, n)
		}
	}
	// A marker that equals or contains a managed value would itself carry it.
	for _, marker := range []string{managedHeaderMaskedText, "[masked]", "[*]", ""} {
		if p.maskedText = marker; marker == "" || (!p.equalsValue(marker) && !p.contain.find(marker)) {
			break
		}
	}
	for _, marker := range []string{managedHeaderMaskedURLPart, "[*]", "-", ""} {
		if p.maskedURLPart = marker; marker == "" || !p.urlTextCarries(marker, true) {
			break
		}
	}
	p.maskedIP = managedHeaderMaskedIP
	for n := 1; p.managedIP(p.maskedIP) && n <= 0xffff; n++ {
		p.maskedIP = "100::" + strconv.FormatInt(int64(n), 16)
	}
	return p
}

func (p *managedHeaderPolicy) managedName(name string) bool {
	if len(name) == 0 || len(name) > managedHeaderNameMaxBytes || !p.nameLens[len(name)] {
		return false
	}
	var buf [managedHeaderNameMaxBytes]byte
	for i := 0; i < len(name); i++ {
		buf[i] = foldByte(name[i])
	}
	_, ok := p.names[string(buf[:len(name)])]
	return ok
}

func (p *managedHeaderPolicy) equalsValue(field string) bool {
	if len(field) == 0 || len(field) > managedHeaderValueMaxBytes || !p.valueLens[len(field)] {
		return false
	}
	var buf [managedHeaderValueMaxBytes]byte
	for i := 0; i < len(field); i++ {
		buf[i] = foldByte(field[i])
	}
	_, ok := p.values[string(buf[:len(field)])]
	return ok
}

// fieldCarries reports whether one Header field value carries a managed
// value, directly or after up to three rounds of CRS-style URL/HTML decoding.
func (p *managedHeaderPolicy) fieldCarries(field string) bool {
	t := trimSpace(field)
	if p.formCarries(t) {
		return true
	}
	// %uXXXX shrinks six bytes to one; nothing longer can decode to a value.
	if len(t) > 6*managedHeaderValueMaxBytes || !strings.ContainsAny(t, "%+&") {
		return false
	}
	for round := 0; round < 3; round++ {
		next := decodeManagedHeaderEscapes(t)
		if next == t {
			return false
		}
		t = trimSpace(next)
		if p.formCarries(t) {
			return true
		}
	}
	return false
}

// formCarries checks a trimmed field and, for lists such as X-Forwarded-For,
// each comma-separated element.
func (p *managedHeaderPolicy) formCarries(t string) bool {
	if p.equalsValue(t) || p.managedIP(t) {
		return true
	}
	if strings.IndexByte(t, ',') < 0 {
		return false
	}
	for rest := t; rest != ""; {
		element := rest
		if i := strings.IndexByte(rest, ','); i >= 0 {
			element, rest = rest[:i], rest[i+1:]
		} else {
			rest = ""
		}
		if element = trimSpace(element); p.equalsValue(element) || p.managedIP(element) {
			return true
		}
	}
	return false
}

// headersCarry checks every field of every managed Header name. A name costs
// one length bit and, rarely, one map probe; unmanaged values are never read.
func (p *managedHeaderPolicy) headersCarry(headers http.Header) bool {
	for name, values := range headers {
		if !p.managedName(name) {
			continue
		}
		for _, value := range values {
			if p.fieldCarries(value) {
				return true
			}
		}
	}
	return false
}

// managedIP reports whether s is an IP, in any textual form, that is managed.
func (p *managedHeaderPolicy) managedIP(s string) bool {
	if len(p.ips) == 0 {
		return false
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	_, ok := p.ips[ip.Unmap()]
	return ok
}

// managedURLScanBytes bounds the URL text redacted before it is truncated to
// limit: a value overlapping the kept bytes, even %uXXXX-encoded, ends within it.
func managedURLScanBytes(text string, limit int) string {
	if n := limit + 6*managedHeaderValueMaxBytes; len(text) > n {
		return text[:n]
	}
	return text
}

// urlScanWindow is managedURLScanBytes for a path, or a request target when
// target is set. A value encoded over several rounds can start in the kept
// bytes yet end past the window, so the segment or parameter the window cuts
// becomes the URL marker when it starts within limit and holds an escape.
func (p *managedHeaderPolicy) urlScanWindow(text string, limit int, target bool) string {
	window := managedURLScanBytes(text, limit)
	if len(window) == len(text) {
		return window
	}
	start := strings.LastIndexByte(window, '/') + 1
	if q := strings.IndexByte(window, '?'); target && q >= 0 {
		start = max(q, strings.LastIndexByte(window, '&')) + 1
	}
	if start < limit && strings.ContainsAny(window[start:], "%&") {
		return window[:start] + p.maskedURLPart
	}
	return window
}

// urlTextCarries reports whether URL text holds a managed value of at least
// managedHeaderContainMinBytes anywhere or, for a request that carried a
// managed value (all), any managed value as a whole token, directly or after
// up to three rounds of CRS-style URL/HTML decoding.
func (p *managedHeaderPolicy) urlTextCarries(text string, all bool) bool {
	t := text
	for round := 0; ; round++ {
		if p.contain.find(t) || all && p.tokenCarries(t) {
			return true
		}
		if round == 3 || !strings.ContainsAny(t, "%+&\x00") {
			return false
		}
		next := decodeManagedHeaderEscapes(t)
		if next == t {
			return false
		}
		t = next
	}
}

// tokenCarries finds a managed value that is the whole text, one of its list
// elements or IP forms, or, when shorter than managedHeaderContainMinBytes
// (contain finds longer ones anywhere), a token in it: not continued by an
// alphanumeric byte on either side where the value's own edge is alphanumeric.
func (p *managedHeaderPolicy) tokenCarries(t string) bool {
	if p.formCarries(trimSpace(t)) || p.ipTokenCarries(t) {
		return true
	}
	var buf [managedHeaderValueMaxBytes]byte
	for i := 0; i < len(t); i++ {
		// An alphanumeric byte after another starts no token.
		if i > 0 && isAlnum(t[i-1]) && isAlnum(t[i]) {
			continue
		}
		for _, n := range p.lengths {
			end := i + n
			if end > len(t) {
				break
			}
			for j := 0; j < n; j++ {
				buf[j] = foldByte(t[i+j])
			}
			_, ok := p.values[string(buf[:n])]
			if !ok && p.plusTokens != nil {
				_, ok = p.plusTokens[string(buf[:n])]
			}
			if !ok {
				continue
			}
			if end < len(t) && isAlnum(t[end-1]) && isAlnum(t[end]) {
				continue
			}
			return true
		}
	}
	return false
}

// ipTokenCarries finds a managed IP, in any textual form, among the maximal
// runs of IP-literal bytes in t: hex digits, ':' and '.' (IPv6), and digits
// and '.' (IPv4, which adjacent hex letters would otherwise hide).
func (p *managedHeaderPolicy) ipTokenCarries(t string) bool {
	if len(p.ips) == 0 {
		return false
	}
	for _, inRun := range []func(byte) bool{
		func(c byte) bool { return isHex(c) || c == ':' || c == '.' },
		func(c byte) bool { return '0' <= c && c <= '9' || c == '.' },
	} {
		for i := 0; i < len(t); {
			j := i
			for j < len(t) && inRun(t[j]) {
				j++
			}
			if j > i && p.managedIP(t[i:j]) {
				return true
			}
			i = j + 1
		}
	}
	return false
}

func isAlnum(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// redactURLPath replaces each path segment carrying a managed value with the
// URL marker; a value spanning segments masks the whole path.
func (p *managedHeaderPolicy) redactURLPath(path string, all bool) string {
	if !p.urlTextCarries(path, all) {
		return path
	}
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment != "" && p.urlTextCarries(segment, all) {
			segments[i] = p.maskedURLPart
		}
	}
	if out := strings.Join(segments, "/"); !p.urlTextCarries(out, all) {
		return out
	}
	return "/" + p.maskedURLPart
}

// redactURLQuery masks the whole query of a request that carried a managed
// value; otherwise each parameter carrying one, or the whole query when a
// value spans parameters.
func (p *managedHeaderPolicy) redactURLQuery(query string, all bool) string {
	if query == "" {
		return ""
	}
	if all {
		return p.maskedURLPart
	}
	return p.redactURLParams(query, false)
}

// redactURLParams replaces each parameter carrying a managed value with the
// URL marker, or the whole query when a value spans parameters.
func (p *managedHeaderPolicy) redactURLParams(query string, all bool) string {
	if query == "" || !p.urlTextCarries(query, all) {
		return query
	}
	params := strings.Split(query, "&")
	for i, param := range params {
		if param != "" && p.urlTextCarries(param, all) {
			params[i] = p.maskedURLPart
		}
	}
	if out := strings.Join(params, "&"); !p.urlTextCarries(out, all) {
		return out
	}
	return p.maskedURLPart
}

// redactURLTarget applies redactURLPath and redactURLQuery to a path and its
// query. A value holding a literal '?' sent raw is split between the path's
// last segment and the first parameter: both become the marker, or the whole
// path and query when the value reaches further.
func (p *managedHeaderPolicy) redactURLTarget(path, query string, hasQuery, all bool) (string, string) {
	redacted := p.redactURLPath(path, all)
	if !hasQuery {
		return redacted, ""
	}
	out := p.redactURLQuery(query, all)
	if !p.question {
		return redacted, out
	}
	params := out
	if all {
		params = p.redactURLParams(query, true)
	}
	if !p.urlTextCarries(redacted+"?"+params, all) {
		return redacted, out
	}
	segment := path[strings.LastIndexByte(path, '/')+1:]
	first, rest, hasRest := strings.Cut(query, "&")
	if p.urlTextCarries(segment, all) || p.urlTextCarries(first, all) || !p.urlTextCarries(segment+"?"+first, all) {
		return "/" + p.maskedURLPart, p.maskedURLPart
	}
	redacted = redacted[:strings.LastIndexByte(redacted, '/')+1] + p.maskedURLPart
	if !all && hasRest {
		out = p.maskedURLPart + "&" + p.redactURLParams(rest, false)
	} else {
		out = p.maskedURLPart
	}
	if p.urlTextCarries(redacted+"?"+out, all) {
		return "/" + p.maskedURLPart, p.maskedURLPart
	}
	return redacted, out
}

// redactURI applies redactURLTarget to a request target.
func (p *managedHeaderPolicy) redactURI(uri string, all bool) string {
	path, query, hasQuery := strings.Cut(uri, "?")
	path, query = p.redactURLTarget(path, query, hasQuery, all)
	if !hasQuery {
		return path
	}
	return path + "?" + query
}

// foldMatcher finds any of its ASCII-lowercase patterns (each at least
// managedHeaderContainMinBytes long) in a text, case-insensitively. A bitset
// over the first two folded bytes rejects almost every position before the
// eight-byte prefix map is probed.
type foldMatcher struct {
	first    [1 << 10]uint64
	patterns map[uint64][]string
}

func (m *foldMatcher) add(pattern string) {
	if m.patterns == nil {
		m.patterns = map[uint64][]string{}
	}
	pair := uint32(pattern[0])<<8 | uint32(pattern[1])
	m.first[pair>>6] |= 1 << (pair & 63)
	key := foldPrefix8(pattern)
	m.patterns[key] = append(m.patterns[key], pattern)
}

func (m *foldMatcher) find(text string) bool {
	if len(m.patterns) == 0 {
		return false
	}
	for i := 0; i+managedHeaderContainMinBytes <= len(text); i++ {
		pair := uint32(foldByte(text[i]))<<8 | uint32(foldByte(text[i+1]))
		if m.first[pair>>6]&(1<<(pair&63)) == 0 {
			continue
		}
		for _, pattern := range m.patterns[foldPrefix8(text[i:])] {
			if len(text)-i >= len(pattern) && equalFoldedASCII(text[i:i+len(pattern)], pattern) {
				return true
			}
		}
	}
	return false
}

func foldByte(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		b[i] = foldByte(c)
	}
	return string(b)
}

func foldPrefix8(s string) uint64 {
	var key uint64
	for i := 0; i < managedHeaderContainMinBytes; i++ {
		key = key<<8 | uint64(foldByte(s[i]))
	}
	return key
}

// equalFoldedASCII compares s, folded, with an already folded pattern.
func equalFoldedASCII(s, folded string) bool {
	for i := 0; i < len(folded); i++ {
		if foldByte(s[i]) != folded[i] {
			return false
		}
	}
	return true
}

// decodeManagedHeaderEscapes is one round of the decoding CRS applies to
// request Headers: urlDecodeUni, HTML entities, then removeNulls.
func decodeManagedHeaderEscapes(s string) string {
	if strings.ContainsAny(s, "%+") {
		s = urlDecodeUni(s)
	}
	if strings.IndexByte(s, '&') >= 0 {
		s = html.UnescapeString(s)
	}
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	return s
}

// urlDecodeUni mirrors Coraza v3's transformation of the same name: %XX,
// IIS %uXXXX (lower byte, full-width ASCII folded back), and "+" as a space.
func urlDecodeUni(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c == '+':
			out = append(out, ' ')
			i++
		case c != '%':
			out = append(out, c)
			i++
		case i+1 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U'):
			if i+5 < len(s) && isHex(s[i+2]) && isHex(s[i+3]) && isHex(s[i+4]) && isHex(s[i+5]) {
				b := hexPair(s[i+4], s[i+5])
				if b > 0 && b < 0x5f && (s[i+2] == 'f' || s[i+2] == 'F') && (s[i+3] == 'f' || s[i+3] == 'F') {
					b += 0x20
				}
				out = append(out, b)
				i += 6
			} else {
				out = append(out, s[i], s[i+1])
				i += 2
			}
		case i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			out = append(out, hexPair(s[i+1], s[i+2]))
			i += 3
		default:
			out = append(out, c)
			i++
		}
	}
	return string(out)
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func hexPair(a, b byte) byte { return hexValue(a)<<4 | hexValue(b) }

func hexValue(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// managedHeaderState is one request's privacy state: the policy of the first
// generation that captured it, and a monotonic flag set once any observed
// managed Header carried a managed value. It lives in the request's holder;
// the bridge registry only indexes it by WAF transaction ID.
type managedHeaderState struct {
	policy *managedHeaderPolicy // nil only for the fail-closed state
	masked atomic.Bool
}

func newManagedHeaderState(policy *managedHeaderPolicy, headers http.Header) *managedHeaderState {
	s := &managedHeaderState{policy: policy}
	s.observe(headers)
	return s
}

// Later Headers can only add masking, never remove it.
func (s *managedHeaderState) observe(headers http.Header) {
	if s.policy == nil || s.masked.Load() {
		return
	}
	if s.policy.headersCarry(headers) {
		s.masked.Store(true)
	}
}

// redact returns "" when text must not reach telemetry: the request carried a
// managed value (CRS transforms can rewrite it, so all of its text is
// withheld), or the text itself contains one.
func (s *managedHeaderState) redact(text string) string {
	if text == "" || s.masked.Load() || s.policy == nil || s.policy.urlTextCarries(text, false) {
		return ""
	}
	return text
}

var failClosedManagedHeaderState = func() *managedHeaderState {
	s := new(managedHeaderState)
	s.masked.Store(true)
	return s
}()

func (h *defenseSnapshotHolder) capturePrivacy(policy *managedHeaderPolicy, headers http.Header) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.privacy == nil {
		h.privacy = newManagedHeaderState(policy, headers)
		return
	}
	// The first generation's policy stays authoritative for this request.
	h.privacy.observe(headers)
}

func requestManagedHeaderState(r *http.Request) *managedHeaderState {
	holder := requestDefenseHolder(r)
	if holder == nil {
		return nil
	}
	holder.mu.RLock()
	defer holder.mu.RUnlock()
	return holder.privacy
}

// requestTelemetryIdentity holds the Header-derived fields request telemetry
// records; any carrying a managed value is replaced by a marker.
type requestTelemetryIdentity struct {
	userAgent   string
	forwardedIP string
	hashIP      string
}

func telemetryIdentity(r *http.Request) requestTelemetryIdentity {
	id := requestTelemetryIdentity{userAgent: r.UserAgent(), forwardedIP: forwardedIP(r), hashIP: clientIP(r)}
	state := requestManagedHeaderState(r)
	if state == nil || state.policy == nil {
		return id
	}
	policy := state.policy
	if id.userAgent != "" && (policy.fieldCarries(id.userAgent) || policy.containInUserAgent.find(id.userAgent)) {
		id.userAgent = policy.maskedText
	}
	if id.forwardedIP != "::" && policy.managedIP(id.forwardedIP) {
		id.forwardedIP = policy.maskedIP
	}
	// clientIP took the rightmost X-Forwarded-For entry; when that entry is
	// managed, hash the connection address instead.
	if r.Header.Get("X-Forwarded-For") != "" && policy.fieldCarries(id.hashIP) {
		id.hashIP = r.RemoteAddr
	}
	return id
}

// telemetryPath is the request path telemetry records: a managed value in it
// is replaced by the URL marker (see redactURLTarget). A path longer than the
// scan window is recorded as the redacted window, so path_bucket (which reads
// segments past the kept bytes) never sees text the scan did not, and a
// segment the window cuts past the kept bytes, which could be a value's
// prefix, becomes the marker.
func telemetryPath(r *http.Request) string {
	path := r.URL.Path
	state := requestManagedHeaderState(r)
	if path == "" || state == nil || state.policy == nil {
		return path
	}
	policy := state.policy
	window := policy.urlScanWindow(path, requestEventPathMaxBytes, false)
	cut := managedURLScanBytes(path, requestEventPathMaxBytes)
	if len(cut) < len(path) && path[len(cut)] != '/' {
		if start := strings.LastIndexByte(cut, '/') + 1; start >= requestEventPathMaxBytes {
			window = cut[:start] + policy.maskedURLPart
		}
	}
	// Only a value holding a '?' reaches the path from the query, and a value
	// split at '?' starts within its encoded length of the end of the path, so
	// a path longer than the window keeps no part of it.
	hasQuery := policy.question && len(cut) == len(path) && (r.URL.RawQuery != "" || r.URL.ForceQuery)
	out, _ := policy.redactURLTarget(window, managedURLScanBytes(r.URL.RawQuery, 0), hasQuery, state.masked.Load())
	return out
}

// managedHeaderRegistry indexes live WAF transactions to their request's
// state. It has no capacity limit: each entry belongs to an in-flight WAF
// transaction and is removed by the connector's deferred release, so its size
// follows concurrent requests, and long-lived ones (WebSockets) never displace
// another request's entry.
type managedHeaderRegistry struct {
	seed   maphash.Seed
	shards [64]managedHeaderRegistryShard
}

type managedHeaderRegistryShard struct {
	mu      sync.RWMutex
	entries map[string]*managedHeaderRegistryEntry
}

type managedHeaderRegistryEntry struct {
	state    *managedHeaderState
	refs     int
	poisoned bool
}

func newManagedHeaderRegistry() *managedHeaderRegistry {
	r := &managedHeaderRegistry{seed: maphash.MakeSeed()}
	for i := range r.shards {
		r.shards[i].entries = make(map[string]*managedHeaderRegistryEntry)
	}
	return r
}

var corazaPrivacyRegistry = newManagedHeaderRegistry()

func (r *managedHeaderRegistry) shard(id string) *managedHeaderRegistryShard {
	return &r.shards[maphash.String(r.seed, id)%uint64(len(r.shards))]
}

func (r *managedHeaderRegistry) bind(id string, state *managedHeaderState) func() {
	if id == "" || len(id) > 128 {
		return func() {}
	}
	shard := r.shard(id)
	shard.mu.Lock()
	entry := shard.entries[id]
	if entry != nil {
		// A reused ID would mix two requests' states: mask both until released.
		entry.poisoned = true
		entry.refs++
	} else {
		entry = &managedHeaderRegistryEntry{state: state, refs: 1}
		shard.entries[id] = entry
	}
	shard.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			shard.mu.Lock()
			entry.refs--
			if entry.refs == 0 && shard.entries[id] == entry {
				delete(shard.entries, id)
			}
			shard.mu.Unlock()
		})
	}
}

// lookup returns the state bound to id (nil when poisoned) and whether id is bound.
func (r *managedHeaderRegistry) lookup(id string) (*managedHeaderState, bool) {
	shard := r.shard(id)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	entry := shard.entries[id]
	if entry == nil {
		return nil, false
	}
	if entry.poisoned {
		return nil, true
	}
	return entry.state, true
}

func (r *managedHeaderRegistry) len() int {
	n := 0
	for i := range r.shards {
		r.shards[i].mu.RLock()
		n += len(r.shards[i].entries)
		r.shards[i].mu.RUnlock()
	}
	return n
}

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

// Bind links a WAF transaction to its request's state and re-checks the
// Headers the WAF is about to inspect. A request without captured privacy
// state binds the fail-closed state, which masks all text.
func (b *CorazaPrivacyBridge) Bind(id string, r *http.Request) func() {
	state := requestManagedHeaderState(r)
	if state == nil {
		state = failClosedManagedHeaderState
	}
	state.observe(r.Header)
	return b.state().bind(id, state)
}

// Redact returns text unchanged, or "" when it must not reach telemetry. An
// unbound or reused transaction ID always returns "".
func (b *CorazaPrivacyBridge) Redact(id, text string) string {
	state, _ := b.state().lookup(id)
	if state == nil {
		return ""
	}
	return state.redact(text)
}

// bound reports whether the connector bound this transaction, i.e. its WAF ran
// with managed Header privacy, whatever audit log parts it recorded.
func (b *CorazaPrivacyBridge) bound(id string) bool {
	_, ok := b.state().lookup(id)
	return ok
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
