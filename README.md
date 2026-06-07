# apx-caddy-challenge

Interactive proof-of-work (PoW) challenge handler for Caddy, used by the
Approximated `challenge` defense effect. Serves a JS PoW page to suspicious
traffic; a solved, HMAC-signed cookie lets the client through for 10 minutes.
Stateless server-side (the cookie is the proof — no challenge table).

## Modules

- App `apx_challenge` — holds `difficulty`, reads the per-cluster HMAC secret
  from `APX_CHALLENGE_SECRET` (env), and the `verify_path`.
- HTTP handler `http.handlers.apx_challenge` — invoked by the per-dimension
  challenge routes (ip/sni/path) + the verify route that Phoenix config-gen
  emits when the cluster image carries the `challenge` token.

## How it works

1. A request matched by a `challenge` route hits the handler. If it carries a
   valid `apx-challenge` cookie (HMAC over `{exp, /24-or-/64 prefix}`, 10-min
   TTL), it's forwarded upstream (`passed_recently`).
2. Otherwise the handler serves a self-contained HTML page whose JS brute-forces
   a SHA-256 leading-zero-bits PoW (`difficulty` bits, default 16), then submits
   the solution via a native form POST to `verify_path`.
3. The verify endpoint re-checks the signed challenge token (signature, expiry,
   client-prefix) and the PoW (against the server's configured difficulty), sets
   the `apx-challenge` cookie, and 303-redirects to the original URL.
4. Non-browser clients (CORS fetches / non-HTML Accept) get `429
   {"error":"challenge_required","retry_after":30}`; WebSocket/SSE get `503
   Retry-After: 30`.

The handler sets the `apx_challenge_outcome` request var
(`issued | passed | passed_recently | failed`) for the apx-caddy-stats recorder
(Phase 9c).

## Config (emitted by Phoenix — not hand-written)

    "apps": { "apx_challenge": {
      "difficulty": 16,
      "secret_env_var": "APX_CHALLENGE_SECRET",
      "verify_path": "/__apx_challenge/verify"
    } }

Routes use `{"handler": "apx_challenge"}` (terminal). The verify route is emitted
first so the solution POST always reaches the handler.

## Build (xcaddy — image step)

Build into the same image as apx-caddy-stats; the image tag MUST include a
`challenge` token (so Phoenix self-gates config emission on it):

    xcaddy build \
      --with github.com/Approximated-Inc/apx-caddy-stats=/path/to/apx-caddy-stats \
      --with github.com/Approximated-Inc/apx-caddy-challenge=/path/to/apx-caddy-challenge \
      ... (other --with modules)

- Build `--platform linux/amd64` for Fly.
- Tag must contain `challenge` as a hyphen-delimited token (e.g.
  `...-coraza4.10-stats-challenge-v1`) so `ProxyServers.image_tag_has_module?`
  matches and Phoenix emits the challenge config.
- Pins: Go 1.26.1, Caddy v2.11.3 (kept in sync with apx-caddy-stats so xcaddy
  resolves one Caddy version).

## Deploy requirement

The deploy pipeline MUST set the Fly secret `APX_CHALLENGE_SECRET` per app to
that cluster's `proxy_servers.challenge_secret`. Phoenix config-gen generates
the DB value on first run when the image carries the token; the secret never
appears in the emitted JSON (only the env-var name does). Rotating the secret
invalidates outstanding cookies (10-min TTL bounds the re-challenge wave).

## Scope (v1)

Enforces **ip / sni / path** challenge. **ja3/ja4 challenge is NOT served** —
TLS fingerprints are caddy-l4 connection vars that aren't surfaced to the HTTP
layer, so a fingerprint challenge fails **open** (traffic passes un-challenged).
To deny a fingerprint, use a `block` rule (enforced at L4). Enabling fingerprint
challenge later requires propagating `tls_ja3`/`tls_ja4` across the L4→L7 hop
(e.g. PROXY-protocol TLVs) — a separate slice.

## Test

    go test ./...

Go tests cover PoW solve/verify, cookie/token HMAC (incl. cross-protocol +
prefix binding), the handler (serve/verify/cookie-gate/non-browser/outcome var),
and page rendering. The real browser solve-and-redirect (incl. slow network +
budget mobile to validate difficulty-16 solve time) is verified on the canary,
not in CI.
