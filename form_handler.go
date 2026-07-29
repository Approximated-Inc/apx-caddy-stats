package apxchallenge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	// formOutcomeVarKey is the caddyhttp var the protection handler writes for
	// downstream logging/analytics.
	formOutcomeVarKey = "apx_form_outcome"
	// formTokenField is the hidden form field the widget injects.
	formTokenField = "_apx_form_token"
	// formTokenHeader carries the token for fetch/JSON submitters.
	formTokenHeader = "X-Apx-Form-Token"

	formWidgetPath    = "/__apx_form/widget.js"
	formChallengePath = "/__apx_form/challenge"
	formTokenPath     = "/__apx_form/token"

	// formWidgetVersion bumps whenever assets/form_widget.js or the substituted
	// paths change; it is the ETag basis so caches revalidate on a new build.
	formWidgetVersion = "1"
)

// ---------------------------------------------------------------------------
// FormEndpointHandler — terminal handler for the three widget endpoints.
// ---------------------------------------------------------------------------

// FormEndpointHandler serves the form-protection widget script and the
// challenge/token minting endpoints. It is terminal: it always writes a
// response and never calls next.
type FormEndpointHandler struct {
	logger *zap.Logger
	app    AppRef
}

func (*FormEndpointHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apx_form_endpoints",
		New: func() caddy.Module { return new(FormEndpointHandler) },
	}
}

func (h *FormEndpointHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.app == nil {
		app, err := resolveApp(ctx)
		if err != nil {
			return err
		}
		h.app = app
	}
	return nil
}

func (h *FormEndpointHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

func (h *FormEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == formWidgetPath:
		return h.serveWidget(w, r)
	case r.Method == http.MethodPost && r.URL.Path == formChallengePath:
		return h.serveChallenge(w, r)
	case r.Method == http.MethodPost && r.URL.Path == formTokenPath:
		return h.serveToken(w, r)
	}
	w.WriteHeader(http.StatusNotFound)
	return nil
}

func (h *FormEndpointHandler) serveWidget(w http.ResponseWriter, r *http.Request) error {
	etag := `"apxform-` + formWidgetVersion + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	body := renderFormWidget(formChallengePath, formTokenPath)
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
	return nil
}

func (h *FormEndpointHandler) serveChallenge(w http.ResponseWriter, r *http.Request) error {
	ip := clientIP(r)
	difficulty := h.app.FormDifficulty()
	challenge := IssueFormChallenge(h.app.Secret(), ip, difficulty, time.Now().Add(h.app.FormTokenTTL()))
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":  challenge,
		"difficulty": difficulty,
	})
	return nil
}

func (h *FormEndpointHandler) serveToken(w http.ResponseWriter, r *http.Request) error {
	ip := clientIP(r)
	_ = r.ParseForm()
	challenge := r.FormValue("challenge")
	solution := r.FormValue("solution")
	probesRaw := r.FormValue("probes")

	payload, err := VerifyFormChallenge(h.app.Secret(), challenge, ip)
	if err != nil {
		return refuse(w, "challenge_invalid", "bad_challenge")
	}
	if !VerifyPoW(challenge, solution, payload.Diff) {
		return refuse(w, "pow_invalid", "bad_solution")
	}

	var probes Probes
	if err := json.Unmarshal([]byte(probesRaw), &probes); err != nil {
		return refuse(w, "probes_invalid", "bad_probes")
	}
	if ok, reason := ScoreProbes(probes, h.app.FormScoring(), h.app.FormMinFillMs()); !ok {
		return refuse(w, "probe_failed", reason)
	}

	host := hostOnly(r.Host)
	ttl := h.app.FormTokenTTL()
	token := IssueFormToken(h.app.Secret(), ip, host, payload.Nonce, time.Now().Add(ttl))
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_in": int(ttl.Seconds()),
	})
	return nil
}

// refuse writes a 200 with {error, reason} and NO token. The widget injects
// nothing, so the later protected POST is blocked. 200 (not 4xx) keeps the
// widget's fail-open path from surfacing errors to the page.
func refuse(w http.ResponseWriter, errCode, reason string) error {
	writeJSON(w, http.StatusOK, map[string]any{"error": errCode, "reason": reason})
	return nil
}

// ---------------------------------------------------------------------------
// FormProtectionHandler — gates the matched protected POST.
// ---------------------------------------------------------------------------

// FormProtectionHandler validates the injected token on a request the config-gen
// route already scoped to a protected path+method. Mode is "enforce" (block
// non-passing) or "monitor" (record outcome, always forward).
type FormProtectionHandler struct {
	Mode string `json:"mode,omitempty"`

	logger *zap.Logger
	app    AppRef
	replay *NonceLRU
}

func (*FormProtectionHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apx_form_protection",
		New: func() caddy.Module { return new(FormProtectionHandler) },
	}
}

func (h *FormProtectionHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.app == nil {
		app, err := resolveApp(ctx)
		if err != nil {
			return err
		}
		h.app = app
	}
	if h.replay == nil {
		h.replay = h.app.ReplayLRU()
	}
	if h.Mode != "monitor" {
		h.Mode = "enforce"
	}
	return nil
}

func (h *FormProtectionHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

func (h *FormProtectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := clientIP(r)
	host := hostOnly(r.Host)

	token := h.extractToken(r)
	outcome := "missing"
	if token != "" {
		if p, err := VerifyFormToken(h.app.Secret(), token, ip, host); err != nil {
			// VerifyFormToken folds expiry into a generic invalid error; we do not
			// separately emit "expired" (see task report).
			outcome = "invalid"
		} else if h.replay.Seen(p.Nonce) {
			outcome = "replayed"
		} else {
			outcome = "passed"
		}
	}
	setFormOutcome(r, outcome)

	if h.Mode == "monitor" || outcome == "passed" {
		return next.ServeHTTP(w, r)
	}
	return h.block(w, r)
}

func (h *FormProtectionHandler) block(w http.ResponseWriter, r *http.Request) error {
	if isLikelyAPIClient(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"form_protection_failed"}`)
		return nil
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, "<!doctype html><meta charset=utf-8><title>Blocked</title><p>This form submission was blocked.</p>")
	return nil
}

// extractToken returns the form token from the X-Apx-Form-Token header (always
// honored) or, for urlencoded/multipart bodies within the cap, from the parsed
// body. When it reads the body it RESTORES it so reverse_proxy forwards the
// untouched request; an over-cap or unknown-length body is left untouched and
// only the header is consulted.
func (h *FormProtectionHandler) extractToken(r *http.Request) string {
	if t := r.Header.Get(formTokenHeader); t != "" {
		return t
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/x-www-form-urlencoded" && mediaType != "multipart/form-data") {
		return ""
	}
	if r.Body == nil {
		return ""
	}
	bodyCap := h.app.FormBodyCap()
	// Unknown length (chunked) or over-cap: skip body parsing, leave body intact.
	if r.ContentLength < 0 || r.ContentLength > bodyCap {
		return ""
	}

	// ContentLength is within cap; buffer it (bounded) and restore for upstream.
	buf, err := io.ReadAll(io.LimitReader(r.Body, bodyCap))
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(buf))
		r.ContentLength = int64(len(buf))
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	r.ContentLength = int64(len(buf))

	return tokenFromBody(mediaType, r.Header.Get("Content-Type"), buf, bodyCap)
}

func tokenFromBody(mediaType, contentType string, buf []byte, bodyCap int64) string {
	switch mediaType {
	case "application/x-www-form-urlencoded":
		vals, err := url.ParseQuery(string(buf))
		if err != nil {
			return ""
		}
		return vals.Get(formTokenField)
	case "multipart/form-data":
		_, params, err := mime.ParseMediaType(contentType)
		if err != nil {
			return ""
		}
		boundary := params["boundary"]
		if boundary == "" {
			return ""
		}
		form, err := multipart.NewReader(bytes.NewReader(buf), boundary).ReadForm(bodyCap)
		if err != nil {
			return ""
		}
		defer func() { _ = form.RemoveAll() }()
		if vs := form.Value[formTokenField]; len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

func resolveApp(ctx caddy.Context) (AppRef, error) {
	app, err := ctx.App("apx_challenge")
	if err != nil {
		return nil, fmt.Errorf("apx_form handler requires apx_challenge app: %w", err)
	}
	ca, ok := app.(*ChallengeApp)
	if !ok {
		return nil, fmt.Errorf("apx_form handler: unexpected app type %T", app)
	}
	return ca, nil
}

func setFormOutcome(r *http.Request, outcome string) {
	caddyhttp.SetVar(r.Context(), formOutcomeVarKey, outcome)
}

// hostOnly strips any port from a Host header value.
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

var (
	_ caddy.Provisioner           = (*FormEndpointHandler)(nil)
	_ caddyfile.Unmarshaler       = (*FormEndpointHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*FormEndpointHandler)(nil)

	_ caddy.Provisioner           = (*FormProtectionHandler)(nil)
	_ caddyfile.Unmarshaler       = (*FormProtectionHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*FormProtectionHandler)(nil)
)
