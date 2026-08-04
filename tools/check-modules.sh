#!/usr/bin/env bash
# Verifies a caddy binary registers every apx module ID. Usage: check-modules.sh ./caddy
set -euo pipefail
BIN="${1:?usage: check-modules.sh <caddy-binary>}"
IDS=(apx apx_stats http.handlers.apx_stats http.handlers.apx_gate \
     apx_trace http.handlers.apx_trace \
     http.handlers.apx_trace_mark http.reverse_proxy.transport.apx_trace \
     apx_challenge http.handlers.apx_challenge http.handlers.apx_verify_endpoints \
     http.handlers.apx_verify)
LIST="$("$BIN" list-modules 2>/dev/null)"
rc=0
for id in "${IDS[@]}"; do
  if ! grep -qx "$id" <<<"$LIST"; then echo "MISSING: $id"; rc=1; fi
done
[ $rc -eq 0 ] && echo "all ${#IDS[@]} apx module IDs registered"
exit $rc
