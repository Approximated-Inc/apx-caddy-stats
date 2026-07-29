package apxchallenge

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// formTestApp is an AppRef for the form handlers with FormScoring "off" so the
// probe ruleset never blocks a well-formed mint, and a low FormDifficulty so the
// PoW solve in-test is instant.
type formTestApp struct{}

func (formTestApp) Secret() string              { return "s" }
func (formTestApp) Difficulty() int             { return 8 }
func (formTestApp) VerifyPath() string          { return "/__apx_challenge/verify" }
func (formTestApp) FormDifficulty() int         { return 4 }
func (formTestApp) FormTokenTTL() time.Duration { return 600 * time.Second }
func (formTestApp) FormMinFillMs() int64        { return 800 }
func (formTestApp) FormScoring() string         { return "off" }
func (formTestApp) FormBodyCap() int64          { return 1 << 20 }
func (formTestApp) ReplayLRU() *NonceLRU        { return NewNonceLRU(1024) }

func newFakeApp() AppRef { return formTestApp{} }

func formBody(fields map[string]string) io.Reader {
	v := url.Values{}
	for k, val := range fields {
		v.Set(k, val)
	}
	return strings.NewReader(v.Encode())
}

func postReq(path, ip string, body io.Reader) *http.Request {
	r := httptest.NewRequest("POST", path, body)
	r.RemoteAddr = ip + ":443"
	if body != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return withVars(r)
}

func postReqHost(path, ip, host string, body io.Reader) *http.Request {
	r := postReq(path, ip, body)
	r.Host = host
	return r
}

func nextFn(f func()) caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		f()
		w.WriteHeader(http.StatusOK)
		return nil
	})
}

var emptyNext = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })

// mintToken drives the challenge+token endpoints and returns a valid token bound
// to ip+host. Fails the test on any endpoint error.
func mintToken(t *testing.T, eh *FormEndpointHandler, ip, host string) string {
	t.Helper()

	chReq := postReqHost("/__apx_form/challenge", ip, host, nil)
	chRec := httptest.NewRecorder()
	_ = eh.ServeHTTP(chRec, chReq, emptyNext)
	var ch struct {
		Challenge  string `json:"challenge"`
		Difficulty int    `json:"difficulty"`
	}
	if err := json.Unmarshal(chRec.Body.Bytes(), &ch); err != nil || ch.Challenge == "" {
		t.Fatalf("challenge failed: code=%d body=%s err=%v", chRec.Code, chRec.Body, err)
	}

	sol := SolvePoW(ch.Challenge, ch.Difficulty)
	tokReq := postReqHost("/__apx_form/token", ip, host,
		formBody(map[string]string{"challenge": ch.Challenge, "solution": sol, "probes": `{"fill_ms":5000}`}))
	tokRec := httptest.NewRecorder()
	_ = eh.ServeHTTP(tokRec, tokReq, emptyNext)
	if tokRec.Code != 200 {
		t.Fatalf("token mint failed: %d %s", tokRec.Code, tokRec.Body)
	}
	var tk struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(tokRec.Body.Bytes(), &tk); err != nil || tk.Token == "" {
		t.Fatalf("token missing from mint: body=%s err=%v", tokRec.Body, err)
	}
	return tk.Token
}

func TestFormEndpointMintsAndHandlerAccepts(t *testing.T) {
	app := newFakeApp()
	eh := &FormEndpointHandler{app: app}
	ph := &FormProtectionHandler{app: app, replay: NewNonceLRU(1024), Mode: "enforce"}

	tok := mintToken(t, eh, "203.0.113.5", "shop.example.com")

	// protected POST carrying the token in the body → passes to next AND the
	// restored body must still be fully readable by next (upstream).
	body := formBody(map[string]string{"_apx_form_token": tok, "email": "a@b.c"})
	pReq := postReqHost("/contact", "203.0.113.5", "shop.example.com", body)
	pRec := httptest.NewRecorder()
	called := false
	forwarded := ""
	_ = ph.ServeHTTP(pRec, pReq, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		got, _ := io.ReadAll(r.Body)
		forwarded = string(got)
		w.WriteHeader(http.StatusOK)
		return nil
	}))
	if !called {
		t.Fatalf("valid token should pass to next; got %d", pRec.Code)
	}
	if !strings.Contains(forwarded, "_apx_form_token") || !strings.Contains(forwarded, "email") {
		t.Fatalf("upstream did not receive the full restored body: %q", forwarded)
	}
	if got := outcomeVar(pReq); got != "passed" {
		t.Fatalf("outcome=%q want passed", got)
	}
}

func TestFormHandlerBlocksMissingTokenInEnforce(t *testing.T) {
	app := newFakeApp()
	ph := &FormProtectionHandler{app: app, replay: NewNonceLRU(16), Mode: "enforce"}
	req := postReqHost("/contact", "203.0.113.5", "shop.example.com", formBody(map[string]string{"email": "a@b.c"}))
	rec := httptest.NewRecorder()
	called := false
	_ = ph.ServeHTTP(rec, req, nextFn(func() { called = true }))
	if called || rec.Code != http.StatusForbidden {
		t.Fatalf("missing token must be blocked in enforce: called=%v code=%d", called, rec.Code)
	}
	if got := outcomeVar(req); got != "missing" {
		t.Fatalf("outcome=%q want missing", got)
	}
}

func TestFormHandlerMonitorAlwaysPasses(t *testing.T) {
	app := newFakeApp()
	ph := &FormProtectionHandler{app: app, replay: NewNonceLRU(16), Mode: "monitor"}
	req := postReqHost("/contact", "203.0.113.5", "shop.example.com", formBody(nil))
	rec := httptest.NewRecorder()
	called := false
	_ = ph.ServeHTTP(rec, req, nextFn(func() { called = true }))
	if !called {
		t.Fatal("monitor mode must always call next")
	}
	if got := outcomeVar(req); got != "missing" {
		t.Fatalf("monitor should still record outcome=missing, got %q", got)
	}
}

func TestFormHandlerReplayRejected(t *testing.T) {
	// second use of same token → outcome replayed, blocked in enforce
	app := newFakeApp()
	eh := &FormEndpointHandler{app: app}
	replay := NewNonceLRU(1024)
	ph := &FormProtectionHandler{app: app, replay: replay, Mode: "enforce"}

	tok := mintToken(t, eh, "203.0.113.5", "shop.example.com")

	// first submission passes
	req1 := postReqHost("/contact", "203.0.113.5", "shop.example.com",
		formBody(map[string]string{"_apx_form_token": tok, "email": "a@b.c"}))
	rec1 := httptest.NewRecorder()
	called1 := false
	_ = ph.ServeHTTP(rec1, req1, nextFn(func() { called1 = true }))
	if !called1 {
		t.Fatalf("first use of token should pass; code=%d", rec1.Code)
	}
	if got := outcomeVar(req1); got != "passed" {
		t.Fatalf("first outcome=%q want passed", got)
	}

	// replay: same token again → blocked
	req2 := postReqHost("/contact", "203.0.113.5", "shop.example.com",
		formBody(map[string]string{"_apx_form_token": tok, "email": "a@b.c"}))
	rec2 := httptest.NewRecorder()
	called2 := false
	_ = ph.ServeHTTP(rec2, req2, nextFn(func() { called2 = true }))
	if called2 || rec2.Code != http.StatusForbidden {
		t.Fatalf("replayed token must be blocked: called=%v code=%d", called2, rec2.Code)
	}
	if got := outcomeVar(req2); got != "replayed" {
		t.Fatalf("replay outcome=%q want replayed", got)
	}
}

func TestFormEndpointServesWidget(t *testing.T) {
	eh := &FormEndpointHandler{app: newFakeApp()}
	r := withVars(httptest.NewRequest("GET", "/__apx_form/widget.js", nil))
	rec := httptest.NewRecorder()
	_ = eh.ServeHTTP(rec, r, emptyNext)
	if rec.Code != 200 {
		t.Fatalf("widget code=%d", rec.Code)
	}
	if ct := rec.Result().Header.Get("Content-Type"); !strings.Contains(ct, "application/javascript") {
		t.Fatalf("widget content-type=%q", ct)
	}
	if rec.Result().Header.Get("ETag") == "" {
		t.Fatal("widget missing ETag")
	}
	if !strings.Contains(rec.Body.String(), "_apx_form_token") {
		t.Fatal("widget body missing field name")
	}
}

func TestFormTokenRefusedOnBadPoW(t *testing.T) {
	eh := &FormEndpointHandler{app: newFakeApp()}
	chReq := postReqHost("/__apx_form/challenge", "203.0.113.5", "shop.example.com", nil)
	chRec := httptest.NewRecorder()
	_ = eh.ServeHTTP(chRec, chReq, emptyNext)
	var ch struct {
		Challenge  string `json:"challenge"`
		Difficulty int    `json:"difficulty"`
	}
	_ = json.Unmarshal(chRec.Body.Bytes(), &ch)

	tokReq := postReqHost("/__apx_form/token", "203.0.113.5", "shop.example.com",
		formBody(map[string]string{"challenge": ch.Challenge, "solution": "wrong", "probes": `{"fill_ms":5000}`}))
	tokRec := httptest.NewRecorder()
	_ = eh.ServeHTTP(tokRec, tokReq, emptyNext)
	if tokRec.Code != 200 {
		t.Fatalf("refusal should be HTTP 200, got %d", tokRec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(tokRec.Body.Bytes(), &resp)
	if _, ok := resp["token"]; ok {
		t.Fatalf("refusal must not carry a token: %s", tokRec.Body)
	}
	if resp["error"] == nil {
		t.Fatalf("refusal must carry an error: %s", tokRec.Body)
	}
}

// outcomeVar reads the apx_form_outcome var seeded by withVars.
func outcomeVar(r *http.Request) string {
	vars, _ := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]any)
	if vars == nil {
		return ""
	}
	s, _ := vars[formOutcomeVarKey].(string)
	return s
}
