# Grafana Integration — Design

This document is the locked design for the PAMSignal Grafana integration, tracked in [issue #25](https://github.com/anhtuank7c/pamsignal/issues/25). Implementation artifacts live under `examples/grafana/`.

The goal: an operator with 5+ Linux hosts and zero Loki experience can go from `apt install pamsignal` to a working fleet-wide auth dashboard in under 30 minutes.

## Architecture

```
┌──────────┐     ┌─────────┐     ┌──────┐     ┌─────────┐
│ PAMSignal│ ──> │ journald│ ──> │ Alloy│ ──> │  Loki   │ ──┐
└──────────┘     └─────────┘     └──────┘     └─────────┘   │
                                                            v
                                                       ┌─────────┐
                                                       │ Grafana │
                                                       └─────────┘
```

PAMSignal already emits ECS-aligned structured fields via `sd_journal_send()`. Alloy scrapes journald for `SYSLOG_IDENTIFIER=pamsignal`, promotes a small set of low-cardinality fields to Loki labels, and forwards the rest as a JSON-encoded log line. Grafana queries Loki via LogQL.

No PAMSignal daemon changes are required.

## Schema (what PAMSignal already emits)

Every entry written to the journal by PAMSignal carries the following structured fields:

| Field | Values | Cardinality | Used as |
|---|---|---|---|
| `SYSLOG_IDENTIFIER` | `pamsignal` | 1 | Alloy filter selector |
| `EVENT_ACTION` | `session_opened`, `session_closed`, `login_success`, `login_failure`, `brute_force_detected`, `unknown` | 6 | **Loki label** |
| `EVENT_CATEGORY` | `authentication`, `authentication,session`, `authentication,intrusion_detection` | 3 | log body |
| `EVENT_KIND` | `event`, `alert` | 2 | log body |
| `EVENT_OUTCOME` | `success`, `failure`, `unknown` | 3 | log body |
| `EVENT_SEVERITY` | 3, 4, 5, 8 (numeric) | 4 | log body |
| `EVENT_MODULE` | `pamsignal` | 1 | log body |
| `SERVICE_NAME` | `sshd`, `sudo`, `su`, `login`, `other` | 5 | **Loki label** |
| `USER_NAME` | username | high | log body |
| `USER_TARGET_NAME` | sudo/su target | high | log body |
| `SOURCE_IP` | remote address | high | log body |
| `SOURCE_PORT` | remote port | high | log body |
| `PROCESS_PID` | PID of the auth process | high | log body |
| `HOST_HOSTNAME` | hostname (also journald-native `_HOSTNAME`) | medium | (redundant) |

Source of truth: `src/journal_watch.c` (`emit_brute_force_alert`, `ps_log_event`) and `src/utils.c` (`ps_event_action_str`, `ps_service_str`, `ps_event_outcome_str`).

## Label cardinality plan

Loki indexes labels — high-cardinality labels blow up the index. The plan keeps cardinality bounded.

**Promoted to Loki labels (used in every selector):**

- `app="pamsignal"` — static, set by Alloy
- `host` ← `__journal__hostname` — one per host (bounded by fleet size)
- `service` ← `__journal_service_name` — 5 values
- `event_action` ← `__journal_event_action` — 6 values

Total streams: `~5 × 6 × fleet_size ≈ 30 × N`. Safe up to thousands of hosts.

**Stay in the log body (parsed at query time via `| json`):**

- `SOURCE_IP`, `USER_NAME`, `USER_TARGET_NAME`, `SOURCE_PORT`, `PROCESS_PID`, `EVENT_SEVERITY`, `EVENT_OUTCOME`, `EVENT_KIND`

`event_outcome` and `event_kind` are derivable from `event_action` — there's no point indexing them. Source IP and user name are high-cardinality; querying them on demand is the right tradeoff.

## Dashboard layout

Three rows, top to bottom:

### Row 1 — Fleet pulse (5 stat panels)

The "Friday-afternoon glance." Each panel is a single number, color-coded.

1. **Hosts reporting (last 1h)** — fleet liveness
2. **Successful logins** (range)
3. **Failed logins** (range)
4. **Brute-force alerts** (range) — red if > 0
5. **Privilege escalations** (sudo/su `session_opened`, range)

### Row 2 — Trends (3 time-series)

6. **Login attempts/min** — stacked by `event_outcome` (success vs failure)
7. **Brute-force detections/min** — stacked by `service`
8. **Events/min per host** — stacked area, top-10 hosts; spot the noisy host

### Row 3 — Drill-downs (4 tables + 1 logs panel)

9. **Top 10 source IPs by failed-login count** (parsed `SOURCE_IP`)
10. **Top 10 attacked usernames** (parsed `USER_NAME`)
11. **Recent brute-force alerts** — time, ip-or-actor, attempts, window, service, host
12. **Recent successful root logins** — `event_action="login_success"` AND `USER_NAME="root"`
13. **Live log stream** — pamsignal events filtered by dashboard variables

### Variables (multi-select, default "All")

- `$host` (from `host` label)
- `$service` (from `service` label)
- `$action` (from `event_action` label)

### Default time range

Last 6h. Quick options: 1h / 6h / 24h / 7d / 30d.

## LogQL query patterns

The four-label scheme keeps queries readable:

```logql
# Failed-login rate
count_over_time({app="pamsignal", event_action="login_failure",
                 host=~"$host", service=~"$service"}[1m])

# Brute-force rate by service
sum by (service) (
  count_over_time({app="pamsignal", event_action="brute_force_detected"}[5m])
)

# Top source IPs (parsed from JSON body)
topk(10,
  sum by (source_ip) (
    count_over_time(
      {app="pamsignal", event_action="login_failure"}
      | json source_ip="SOURCE_IP"
      [$__range]
    )
  )
)

# Successful root logins
{app="pamsignal", event_action="login_success", service="sshd"}
  | json user_name="USER_NAME"
  | user_name="root"
```

## Alerts

Shipped in `examples/grafana/alerts.yaml` as Grafana-native rules:

| # | Rule | Severity | Rationale |
|---|---|---|---|
| 1 | Any `event_action="brute_force_detected"` | critical | PAMSignal already validated the threshold; alert is trustworthy |
| 2 | `event_action="login_success"` AND `USER_NAME="root"` on `service="sshd"` | high | Direct root SSH is the canonical "you should care" event |
| 3 | ≥10 `login_failure` from one `SOURCE_IP` in 5 min | high | Safety net if operator tuned `fail_threshold` very high |
| 4 | Host stopped reporting > 10 min | medium | Heartbeat — daemon dead or host offline |

Off-hours login is policy-specific. Out of scope for v1.

## Try-it path (docker-compose)

PAMSignal needs systemd + journald, which is awkward inside containers. The try-it stack avoids this by including a **synthetic event producer** (small Python container) that pushes pamsignal-shaped log lines directly to Loki via the HTTP push API. This is enough to demo the dashboard and run CI.

The "real PAMSignal" path is documented in `examples/grafana/README.md` and uses Alloy installed on the host.

## Deliverable layout

```
examples/grafana/
├── README.md              — integration guide (Loki-newcomer friendly)
├── alloy.river            — Alloy config: journald → Loki
├── dashboards/
│   └── pamsignal-v1.json  — the dashboard
├── alerts.yaml            — Grafana alert rules
├── docker-compose.yml     — Loki + Alloy + Grafana try-it stack
├── synthetic/             — synthetic event producer (try-it & CI)
│   ├── Dockerfile
│   └── produce.py
└── verify.sh              — one-command integration health check
```

## Success criteria

Reproduced from the issue for tracking convenience:

1. Operator with 5+ Linux VPSes and zero Loki experience reaches a working dashboard in under 30 minutes following the guide.
2. The dashboard answers "what's happening with auth across my fleet right now?" at a glance.
3. The grafana.com listing reaches 1k+ downloads in the first 3 months.
4. At least one outside contributor opens a PR improving the integration.
5. CI proves the integration still works on every Grafana / Loki / Alloy update.
