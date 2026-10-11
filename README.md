# apx-caddy-stats

Copyright © Approximated Inc. All rights reserved.

No permission is granted to use, copy, modify, merge, publish, distribute,
sublicense, or sell copies of this software or any associated files without
prior written permission from the copyright holder.

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
or after up to three rounds of CRS-style URL/HTML decoding, is masked too. A
value's `+` also matches a space, as CRS decodes it. `request_events.ua` is
masked when it is a managed value or embeds one managed under another Header
name; `forwarded_ip` and the unique-client hash IP when they are a managed IP.

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
value encoded over several rounds) becomes `[masked]`. A path with nothing
masked is recorded unchanged, so its `path_bucket` never depends on the scan.
A WAF transaction bound without a privacy state ships `request_uri` as
`/[masked]`.

Masked text is `[masked: managed header value]` and a masked forwarded IP is
`100::` (RFC 6666 discard-only), so masked is distinguishable from absent (`""`,
`::`). If a managed value would itself appear in a marker, the text marker falls
back to `[masked]`, then `[*]`, then `""`, the URL marker to `[*]`, then `-`,
then `""`, and the IP to `100::1`, `100::2`, ...

The stamped `X-Apx-Defense-Evidence` value is
`http=<0|1>;coraza_all=<0|1>;coraza_rule_ids=<ascending ids>`, using only bytes
CRS 920274 accepts at paranoia level 4. Selectors for CRS rules outside this
image's catalog are skipped and logged once when the config loads.
