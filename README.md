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
