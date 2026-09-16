# apx-caddy-stats

Copyright © Approximated Inc. All rights reserved.

No permission is granted to use, copy, modify, merge, publish, distribute,
sublicense, or sell copies of this software or any associated files without
prior written permission from the copyright holder.

## L4 block telemetry

`layer4.handlers.apx_l4_block_stats` records a configured close-rule match.
Place it after PROXY-protocol decoding and immediately before `close`:

```json
{"handle":[{"handler":"apx_l4_block_stats","reason":"ip"},{"handler":"close"}]}
```

The reason is required and must be `ip`, `sni`, `ja3`, or `ja4`. The handler
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
keys keep counting at capacity; additional keys contribute to one overflow
counter emitted with IP `::`, reason `overflow`, and the **flush minute**.
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

Connection-stage hooks keep bounded request-local evidence and emit no raw error
messages, addresses, certificates or headers. The control plane must deploy its
optional-field ingestion, ClickHouse migration and log-reader changes before the
new proxy image is rolled out. Historical rows retain a generic failure outcome.

Coordinate overlapping handler changes with open PR #13 (JA4); keep PR #16's
JSON encoding fix independently mergeable. PR #10 (unified plugin/gate) was
closed without merging; if that work resumes, its separate gate will need
equivalent failure capture. PR status checked on 2026-09-14; this work starts
from the image's `3ae643eb9957d2d7d9bf4cfae81201e35f3381bb` pin.
