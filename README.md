# apx-caddy-stats

Copyright © Approximated Inc. All rights reserved.

No permission is granted to use, copy, modify, merge, publish, distribute,
sublicense, or sell copies of this software or any associated files without
prior written permission from the copyright holder.

## Shutdown and reload

Caddy builds a new `apx_stats` app on every config load and stops the old
one. `Stop()` never waits on the network for long: the flush loop only drains
and encodes, and a separate ship worker POSTs.

- On Stop, an in-flight tick POST is cancelled and its body is retried under
  the shutdown deadline. The final drain is queued behind it.
- `Stop()` waits for the final batch at most `ingest.stop_wait_ms` (default
  2000). A healthy ingest finishes inside that wait, so a graceful shutdown
  loses nothing. Against a hung ingest Stop returns at the wait and the ship
  continues in the background.
- All shipping after Stop (the final batch with `shutdown_max_retries`, and
  each retired-HTTP delivery) is bounded by `ingest.shutdown_deadline_ms`
  (default 30000). The deadline cuts a hung POST at once.
- Stopping and retired generations share two process-wide ship slots. A
  generation that can't get one drops its batch and counts it, so rapid
  reloads against a hung ingest can't pile up goroutines or bodies.
- At most two encoded batches wait to ship. A full queue drops the oldest.

Metrics: `apx_stats_stop_wait_seconds`,
`apx_stats_retired_ship_total{result=ok|deadline|busy|permanent|exhausted}`,
`apx_stats_ship_queue_dropped_rows_total`. Dropped rows also count in
`apx_stats_dropped_rows_total`.

## Overload control

`apps.apx_stats.overload` turns on a node-local overload controller. Absent,
the level reads 0 and nothing changes.

```json
{"overload": {"waf": "observe", "admission": {"mode": "observe"}}}
```

Modes are `off`, `observe` (count only) and `enforce`. Thresholds are plugin
defaults; an optional `thresholds` object overrides them for calibration.

The controller is process-global, so it survives reloads, and changes level
without a reload. Once a second it reads `/proc/stat` steal (and cgroup v2
`throttled_usec`, 10 s EWMA), Go scheduler latency (`/sched/latencies`, p99
over 10 s) and a modelled shared-CPU burst balance.

| Level | Enters on (3 consecutive samples) | Leaves |
|---|---|---|
| 1 conserve | throttle ≥ 100‰, sched p99 ≥ 20 ms, or a calibrated burst balance empty in < 300 s | 120 s calm (throttle < 50‰, sched < 10 ms), after 30 s at the level |
| 2 shed | throttle ≥ 300‰ or sched p99 ≥ 100 ms | 60 s without those, after 30 s; falls to 1 |

The burst model is `uncalibrated` (never triggers) until a throttle onset or a
fresh process (uptime < 120 s), and `unthrottled` when the node drains past
the largest balance without steal.

`apx.overload` is an in-process bridge for the Coraza fork's
`overload_policy`. At level ≥ 1 in enforce mode, `skip` routes (detect mode)
skip WAF evaluation and `skip_static` routes (block mode) skip only static
assets that pass a strict screen: GET/HEAD, no body, a plain path and query,
no injection markers in headers. Observe mode counts would-skip.

The stats batch carries one `node_state` row per completed minute that was
not normal or had a non-zero counter, plus a heartbeat every 10 minutes:

```json
{"_type":"node_state","ts":"2026-10-28T17:10:00Z","proxy_server_id":768,"machine_id":"e2865013c51398","level_max":2,"l1_seconds":40,"l2_seconds":20,"reasons":3,"sched_p99_us_max":180000,"burst_est_s_min":-1,"burst_model":"uncalibrated","inflight_max":412,"admission_limit_min":24,"waf_skipped_detect":5120,"waf_skipped_static":0,"waf_would_skip":0,"shed_p0":0,"shed_p1":3,"shed_p2":88,"shed_p3":940,"would_shed":0,"gomaxprocs":1}
```

`reasons` bits: 1 throttle, 2 sched, 4 burst, 8 admission hard cap.
Metrics: `apx_stats_overload_level`, `apx_stats_overload_waf_skips_total{kind}`.

### Admission

`http.handlers.apx_admission` goes right after `apx_stats` in the stats
wrapper: `[apx_stats, apx_admission, subroute]`. It reads
`overload.admission` (`mode`, optional `min_limit` and `hard_limit`).

- Classes: P0 `/__apx_*`, ACME, `/healthy`, `/apxflyhealthcheck*` (never
  shed); P1 HTML navigations; P3 static assets; P2 everything else.
  WebSocket upgrades and event streams pass through uncounted.
- At level 2 the limit is `clamp(ceil(completions/s, 10 s EWMA), 8, hard)`.
  P3 sheds at in-flight ≥ 0.5 L, P2 at ≥ L, P1 at ≥ 1.5 L.
- The hard cap applies at any level: P2/P3 at `max(256, 2 × MemTotal MB)`,
  P1 at 1.25 × that.
- A shed is `503` with `Retry-After: 1..3`, `Cache-Control: no-store`,
  `apx-overload: 1` and a short body, on a kept-alive connection. It has no
  vhost, so it records no counter row; `node_state.shed_*` counts it.
- Observe mode counts `would_shed` and admits. The admit path allocates
  nothing (≈ 23 ns); a shed takes ≈ 130 ns.

## Request correlation

With request events enabled in `mode_v2`, `request_id` contains Caddy's
per-request UUID from `{http.request.uuid}`. The control plane sets
`X-Apx-Request-Id` to the same placeholder in the reverse proxy's upstream
request headers, replacing client-supplied values. The ID stays the same
across proxy retries; separate incoming requests receive separate IDs.
The stats handler reads Caddy's replacer, never the inbound header.
Legacy event payloads are unchanged.

## L4 block telemetry

`layer4.handlers.apx_l4_block_stats` records a configured close-rule match.
Place it after PROXY-protocol decoding and immediately before `close`:

```json
{"handle":[{"handler":"apx_l4_block_stats","reason":"ip"},{"handler":"close"}]}
```

The reason is required and must be `ip`, `sni`, `ja3`, `ja4`, or `abuseipdb`. The handler
uses the existing `apx_stats` app and records the decoded connection address;
it does not read TLS data or change matching, forwarding, or blocking policy.
Only routes containing the handler record blocks. Existing L4 connection and
fingerprint counters are unchanged.

The normal authenticated gzip/NDJSON flush, including shutdown, carries rows:

```json
{"_type":"l4_block","ts":"2026-09-16T23:00:00Z","proxy_server_id":42,"ip":"203.0.113.9","reason":"ip","connection_count":2}
```

Counts retain the observation minute and aggregate by canonical IP and reason.
IPv4-mapped IPv6 addresses normalize to IPv4; IPv6 scope zones are removed.
Each app instance holds at most 10,000 distinct keys between drains. Existing
keys keep counting at capacity; additional keys contribute to fixed source
scalars emitted with IP `::` and the **flush minute**. Reputation closes use
`reason=abuseipdb`; their capped increments use `reason=abuseipdb_overflow`.
Existing close reasons keep `reason=overflow`. The handler cannot configure
either overflow reason. Both sources share the same 10,000-key cap; only two
scalar overflow counters exist. Source-specific reputation rows require a
cluster-scoped analytics credential.
Overflow has no client attribution or exact observation minute, so report
windows must account for this timing limitation. Admission and drain share a
mutex, and key sizes are bounded independently of caller-controlled strings.

These are matched configured closes, not all failed TLS handshakes, network
failures, or proof of upstream success. Delivery uses the existing best-effort
flush transport; exhausted retries can lose a batch. No heartbeat is emitted,
so an empty table alone does not establish recorder health.

The consumer, migration, and gated config generator shipped in
[approximated PR #212](https://github.com/Approximated-Inc/approximated/pull/212).
Existing image manifests 1–3 omit this handler; manifest 4 is reserved for an
image containing it. To roll out:

1. Merge this producer PR, then pin its full immutable commit in the fleet
   Dockerfile. Keep the deployed Caddy and other plugin pins unchanged.
2. Build and probe an `apxm4` image, including real PROXY-protocol close and
   telemetry delivery. Do not apply manifest 4 to an older binary.
3. Canary one approved cluster through the normal image rollout workflow;
   verify every machine's image and loaded config, then fresh `l4_blocks_1m`
   rows and overflow reporting before expanding.
4. Roll back through the normal workflow to the recorded previous image and
   capability-compatible config. Confirm recorder handlers are removed before
   an old binary is asked to load that config.

The producer change itself does not publish an image or activate recording.

## Upstream failure reasons in request logs

With request events enabled in `mode_v2`, failed proxy requests can include
`upstream_failure_reason`. This optional field is omitted for successful
requests and legacy events; disposition and sampling rules are unchanged.

Reasons: `dns_timeout`, `dns_error`, `connect_timeout`, `connection_refused`,
`connection_reset`, `tls_certificate_error`, `tls_handshake_timeout`,
`tls_handshake_error`, `request_write_timeout`, `request_write_error`,
`response_header_timeout`, `upstream_eof`, `no_upstreams_available`, `unknown`.

The reason describes the proxy's observed failure, not which network operator
caused it. Only the final error before response headers is classified. An origin
HTTP 5xx response and a successful retry do not acquire a transport failure reason.
Client cancellation is excluded. Failures while streaming a response body are
outside this version's scope. When the available error evidence cannot identify
the reason, the category is `unknown`; elapsed time is never used to guess.

Caddy preserves typed errors from its normal HTTP transport. Some custom
transports or response handlers erase that evidence. In particular, a plain error
from a custom `handle_response` handler is indistinguishable from a transport
error at the outer handler and can retain a proxy-failure classification with
either an unknown or typed reason. Built-in
response-handler errors and exhausted response-based retries are excluded using
the pinned Caddy error metadata, covered by integration tests.

When the managed Header privacy WAF connector withholds an error's text, the
reason comes from the connection-stage evidence recorded after that request's
last successful connection (a dial or a reused pooled connection) if all of it
agrees, and is `unknown` otherwise. A dial failure followed by a successful
connection, such as a load-balancer retry to another upstream or the other
address family of one hostname, therefore never classifies a later failure.

Connection-stage hooks keep bounded request-local evidence and emit no raw error
messages, addresses, certificates or headers. The control plane must deploy its
optional-field ingestion, ClickHouse migration and log-reader changes before the
new proxy image is rolled out. Historical rows retain a generic failure outcome.

Coordinate overlapping handler changes with open PR #13 (JA4); keep PR #16's
JSON encoding fix independently mergeable. PR #10 (unified plugin/gate) was
closed without merging; if that work resumes, its separate gate will need
equivalent failure capture. PR status checked on 2026-09-14; this work starts
from the image's `3ae643eb9957d2d7d9bf4cfae81201e35f3381bb` pin.

## Managed Header privacy

`apx_defense_evidence` in `capture_privacy` mode receives the Header name/value
pairs of the cluster's Defense rules. Telemetry masks only requests that carry
one: a field of a managed Header name that equals a managed value after
trimming, ASCII case folding and CRS-style URL/HTML decoding (each element of a
comma-separated list; an IP in any textual form). For such a request every WAF
finding's `rule_msg`/`match_data` is masked, since CRS transforms can rewrite the
value. Any finding text containing a managed value of 8 bytes or more, directly
or after up to three rounds of CRS-style URL/HTML decoding, is masked too. In
finding text and URLs (below) a value's `+` also matches a space, as CRS
decodes it. `request_events.ua` is masked when it is a managed value or embeds
one managed under another Header name; `forwarded_ip` and the unique-client
hash IP when they are a managed IP.

The URL is masked by part, keeping its shape. In the WAF finding's
`request_uri` and in `request_events.path`/`path_bucket` (and the Edge Verify
path bucket), a path segment or query parameter that contains a managed value
of 8 bytes or more, directly or after up to three rounds of CRS-style URL/HTML
decoding, becomes `[masked]`, on any request. For a request that carries a
managed value, a segment that holds any managed value as a whole token (or a
managed IP in any textual form) is masked too, and its whole query becomes
`[masked]`. A value spanning segments or parameters masks the whole path or
query. A value holding a literal `?` sent raw is split between the path and
the query: the last path segment and the first parameter both become
`[masked]` (the whole path and query when the value reaches further).
Redaction runs before the URL is truncated, over the kept bytes plus 6 KiB, so
a value straddling the limit is not partly shipped; a segment or parameter that
starts within the limit, holds an escape and is cut by that scan window (a
value encoded over several rounds) becomes `[masked]`. A path longer than that
window is recorded as the redacted window, with a segment the window cuts past
the kept bytes as `[masked]`, so `path_bucket` (which reads segments past the
kept bytes) never sees unscanned text; for such a path it reflects only the
scanned prefix. A WAF transaction bound without a privacy state ships
`request_uri` as `/[masked]`.

Limits: the scan window bounds a value's encoded form, not every obfuscation.
A value padded with `%00` per byte (removed by CRS `removeNulls`) or written as
HTML entities per byte (`&#x..;`) can start in the kept bytes and end past the
window, so a prefix of it may ship. Either requires a client that already
knows the value to encode it deliberately.

Masked text is `[masked: managed header value]` and a masked forwarded IP is
`100::` (RFC 6666 discard-only), so masked is distinguishable from absent (`""`,
`::`). If a managed value would itself appear in a marker, the text marker falls
back to `[masked]`, then `[*]`, then `""`, the URL marker to `[*]`, then `-`,
then `""`, and the IP to `100::1`, `100::2`, ...

The stamped `X-Apx-Defense-Evidence` value is
`http=<0|1>;coraza_all=<0|1>;coraza_rule_ids=<ascending ids>`, using only bytes
CRS 920274 accepts at paranoia level 4. Selectors for CRS rules outside this
image's catalog are skipped and logged once when the config loads.
