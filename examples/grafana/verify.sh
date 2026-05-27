#!/usr/bin/env bash
# verify.sh — confirms a PAMSignal → Loki → Grafana pipeline is healthy.
#
# What it does:
#   1. Emits a synthetic pamsignal-shaped event into the local journal
#      (or pushes one directly to Loki if --loki-only is passed).
#   2. Polls Loki for the event to appear under the expected labels.
#   3. Confirms Grafana can reach the Loki datasource.
#   4. Confirms the pamsignal-v1 dashboard is installed.
#
# Exit codes:
#   0 — healthy
#   1 — event not received by Loki
#   2 — Loki not reachable
#   3 — Grafana not reachable / datasource broken
#   4 — dashboard missing
#
# Usage:
#   ./verify.sh                       # full check (needs systemd-cat or curl)
#   ./verify.sh --loki-only           # skip journald, push direct to Loki
#   LOKI_URL=https://... ./verify.sh  # override endpoints
#   GRAFANA_URL=https://... ./verify.sh

set -euo pipefail

LOKI_URL="${LOKI_URL:-http://localhost:3100}"
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
DASHBOARD_UID="${DASHBOARD_UID:-pamsignal-v1}"
PROBE_PREFIX="${PROBE_PREFIX:-pamsignal-verify}"
POLL_TIMEOUT_SECS="${POLL_TIMEOUT_SECS:-30}"

MODE="full"
if [[ "${1:-}" == "--loki-only" ]]; then
  MODE="loki-only"
fi

probe_id="${PROBE_PREFIX}-$(date +%s)-$$"

red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
dim()    { printf "\033[2m%s\033[0m\n" "$*"; }

step() { printf "\n▸ %s\n" "$*"; }
ok()   { green "  ✓ $*"; }
fail() { red   "  ✗ $*"; }

# ---------------------------------------------------------------------------
# 1. Loki reachable
# ---------------------------------------------------------------------------
step "Checking Loki at ${LOKI_URL}"
if ! curl -sf --max-time 5 "${LOKI_URL}/ready" >/dev/null; then
  fail "Loki not reachable at ${LOKI_URL}/ready"
  fail "Confirm 'docker compose ps' shows loki Healthy, or LOKI_URL=… points at your real instance."
  exit 2
fi
ok "Loki responds at /ready"

# ---------------------------------------------------------------------------
# 2. Emit a probe event
# ---------------------------------------------------------------------------
step "Emitting probe event id=${probe_id}"

emit_via_journal() {
  if ! command -v systemd-cat >/dev/null 2>&1; then
    return 1
  fi
  # systemd-cat doesn't accept structured fields directly. Use logger which
  # can write to journald with the right SYSLOG_IDENTIFIER. The Alloy
  # production pipeline matches on SYSLOG_IDENTIFIER=pamsignal, so this works
  # without needing PAMSignal itself.
  logger -t pamsignal -p user.notice \
    "pamsignal: VERIFY id=${probe_id} synthetic"
  return 0
}

emit_via_loki() {
  local ts_ns
  ts_ns=$(date +%s)000000000
  local body
  body=$(cat <<JSON
{
  "streams": [
    {
      "stream": {
        "app": "pamsignal",
        "host": "verify-$(hostname -s)",
        "service": "verify",
        "event_action": "verify"
      },
      "values": [
        ["${ts_ns}", "{\"MESSAGE\":\"pamsignal verify probe ${probe_id}\",\"EVENT_ACTION\":\"verify\",\"verify_id\":\"${probe_id}\"}"]
      ]
    }
  ]
}
JSON
)
  curl -sf --max-time 5 -X POST -H "Content-Type: application/json" \
    --data-binary "${body}" "${LOKI_URL}/loki/api/v1/push" >/dev/null
}

if [[ "${MODE}" == "full" ]]; then
  if emit_via_journal; then
    ok "Wrote synthetic event to journald (tag=pamsignal)"
    dim "    (Alloy on this host needs to be running for the event to reach Loki)"
  else
    yellow "  ! systemd-cat/logger not available — falling back to direct Loki push"
    emit_via_loki
    ok "Pushed event directly to Loki"
  fi
else
  emit_via_loki
  ok "Pushed event directly to Loki (--loki-only)"
fi

# ---------------------------------------------------------------------------
# 3. Poll Loki for the probe event
# ---------------------------------------------------------------------------
step "Polling Loki for the probe event (timeout ${POLL_TIMEOUT_SECS}s)"

found=0
start_ts=$(date +%s)
while (( $(date +%s) - start_ts < POLL_TIMEOUT_SECS )); do
  # Query the last minute for the probe id in the log body
  end_ns=$(date +%s)000000000
  start_ns=$(( $(date +%s) - 120 ))000000000
  expr='{app="pamsignal"} |~ "'"${probe_id}"'"'
  response=$(curl -sf --max-time 5 --get "${LOKI_URL}/loki/api/v1/query_range" \
    --data-urlencode "query=${expr}" \
    --data-urlencode "start=${start_ns}" \
    --data-urlencode "end=${end_ns}" \
    --data-urlencode "limit=10" || echo '{}')
  count=$(printf '%s' "${response}" | python3 -c "
import sys, json
try:
  d = json.load(sys.stdin)
  print(sum(len(s.get('values', [])) for s in d.get('data', {}).get('result', [])))
except Exception:
  print(0)
" 2>/dev/null || echo 0)
  if (( count > 0 )); then
    found=${count}
    break
  fi
  sleep 1
done

if (( found > 0 )); then
  ok "Loki ingested probe event (${found} match$( [[ ${found} != 1 ]] && echo es ))"
else
  fail "Probe event never reached Loki within ${POLL_TIMEOUT_SECS}s"
  fail "  - If using journald path: check that Alloy is running and its config matches SYSLOG_IDENTIFIER=pamsignal"
  fail "  - If using --loki-only: this is a Loki ingestion problem; check loki logs"
  exit 1
fi

# ---------------------------------------------------------------------------
# 4. Grafana healthy
# ---------------------------------------------------------------------------
step "Checking Grafana at ${GRAFANA_URL}"
if ! curl -sf --max-time 5 "${GRAFANA_URL}/api/health" >/dev/null; then
  yellow "  ! Grafana not reachable at ${GRAFANA_URL} — skipping dashboard check."
  yellow "    (Set GRAFANA_URL=… if Grafana is elsewhere.)"
  green "Pipeline OK (Loki only)"
  exit 0
fi
ok "Grafana /api/health responds"

# ---------------------------------------------------------------------------
# 5. Loki datasource configured
# ---------------------------------------------------------------------------
step "Checking Grafana → Loki datasource"
ds=$(curl -sf --max-time 5 "${GRAFANA_URL}/api/datasources/uid/loki" || echo '{}')
ds_url=$(printf '%s' "${ds}" | python3 -c "
import sys, json
try:
  print(json.load(sys.stdin).get('url', ''))
except Exception:
  pass
" 2>/dev/null || true)
if [[ -z "${ds_url}" ]]; then
  fail "Loki datasource not found in Grafana (uid=loki)"
  exit 3
fi
ok "Loki datasource configured: ${ds_url}"

# ---------------------------------------------------------------------------
# 6. Dashboard installed
# ---------------------------------------------------------------------------
step "Checking PAMSignal dashboard (uid=${DASHBOARD_UID})"
dash=$(curl -sf --max-time 5 "${GRAFANA_URL}/api/dashboards/uid/${DASHBOARD_UID}" || echo '{}')
title=$(printf '%s' "${dash}" | python3 -c "
import sys, json
try:
  d = json.load(sys.stdin)
  print(d.get('dashboard', {}).get('title', ''))
except Exception:
  pass
" 2>/dev/null || true)
if [[ -z "${title}" ]]; then
  fail "Dashboard uid=${DASHBOARD_UID} not found."
  fail "Import dashboards/pamsignal-v1.json into Grafana, or provision via /etc/grafana/provisioning/dashboards/"
  exit 4
fi
ok "Dashboard installed: ${title}"

# ---------------------------------------------------------------------------
echo
green "✅ Pipeline healthy"
echo "   - Loki:        ${LOKI_URL}"
echo "   - Grafana:     ${GRAFANA_URL}"
echo "   - Dashboard:   ${GRAFANA_URL}/d/${DASHBOARD_UID}"
echo "   - Probe ID:    ${probe_id}"
