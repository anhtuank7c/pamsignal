# PAMSignal — Grafana integration

Fleet-wide SSH/sudo/su/login monitoring for PAMSignal, in Grafana.

![PAMSignal dashboard](../../assets/grafana-dashboard.png)

This directory ships everything an operator needs to take PAMSignal events from a
Linux fleet and surface them in a single Grafana dashboard:

- `alloy.river` — production [Grafana Alloy](https://grafana.com/docs/alloy/latest/)
  config. One install per host. Scrapes `SYSLOG_IDENTIFIER=pamsignal` from systemd
  journald and ships to Loki.
- `dashboards/pamsignal-v1.json` — the dashboard. Import or provision.
- `alerts.yaml` — four Grafana-native alert rules.
- `docker-compose.yml` — a single-command local stack so you can see the dashboard
  before you commit to deploying anything.
- `verify.sh` — one-shot health check for your pipeline.

The full design — schema, label-cardinality plan, panel rationale — lives in
[`docs/grafana-integration.md`](../../docs/grafana-integration.md).

---

## Try it out in 60 seconds (no Linux fleet required)

You need Docker. That's it.

```bash
cd examples/grafana
docker compose up -d
```

Open **http://localhost:3000** — anonymous Admin, no login. The dashboard is
under the **PAMSignal** folder. Synthetic events stream in at ~2/sec; brute-force
bursts fire every ~25 seconds on average.

To tear down (including volumes):

```bash
docker compose down -v
```

### What's in the local stack

| Service | Role |
| --- | --- |
| `loki` | Single-binary Loki, filesystem storage, 7-day retention |
| `alloy` | Reads JSONL events from a shared volume; mirrors the production pipeline shape |
| `grafana` | Anonymous Admin, provisioned with Loki + the dashboard |
| `renderer` | Image renderer for `/render` URLs (used by `assets/grafana-dashboard.png`) |
| `synthetic` | Python container generating realistic pamsignal events |

The synthetic producer pushes events into Loki via two paths simultaneously:

1. **Direct push** to `loki/api/v1/push` — simulates what an HTTP-based agent
   would do.
2. **Append to a shared file** that `alloy` tails — proves the production-style
   Alloy pipeline works locally too.

Both paths land in the same Loki instance with the same label set, so the
dashboard works identically against either source.

---

## Deploy for real

### 1. Stand up Loki + Grafana

If you don't already have them, the simplest path is
[Grafana Cloud](https://grafana.com/products/cloud/) (free tier includes Loki).
Self-host with [docker-compose](https://grafana.com/docs/loki/latest/setup/install/docker/)
or [Helm](https://grafana.com/docs/loki/latest/setup/install/helm/).

### 2. Install Alloy on each PAMSignal host

```bash
# Debian/Ubuntu — from grafana.com APT repo
curl -fsSL https://apt.grafana.com/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/grafana.gpg
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
  | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt-get update && sudo apt-get install alloy

# RHEL/Fedora/Alma/Rocky — from grafana.com RPM repo
# https://grafana.com/docs/alloy/latest/set-up/install/linux/
```

The Alloy package ships a `alloy` systemd unit; the user it runs as
(`alloy:alloy`) must be in the `systemd-journal` group to read journald:

```bash
sudo usermod -aG systemd-journal alloy
```

### 3. Drop in `alloy.river`

```bash
sudo cp alloy.river /etc/alloy/config.alloy
# Edit the loki.write endpoint URL for your Loki instance
sudo $EDITOR /etc/alloy/config.alloy
sudo systemctl restart alloy
```

Verify Alloy is happy:

```bash
sudo journalctl -u alloy -f
# Or visit http://<host>:12345 for the Alloy UI
```

### 4. Import the dashboard

**Option A — provision** (recommended for self-hosted Grafana):

```bash
sudo cp dashboards/pamsignal-v1.json /var/lib/grafana/dashboards/
sudo cp ../grafana/provisioning/dashboards/pamsignal.yml \
        /etc/grafana/provisioning/dashboards/
sudo systemctl restart grafana-server
```

**Option B — import via UI**: Grafana → Dashboards → New → Import → upload
`dashboards/pamsignal-v1.json`. Pick your Loki datasource when prompted.

### 5. Wire alerts

Edit `alerts.yaml` to point `folder:` at the Grafana folder you want, then
provision via `/etc/grafana/provisioning/alerting/` or import through the
Grafana UI (Alerting → Alert rules → Import).

After importing, attach each rule to a contact point (Slack, Telegram,
PagerDuty, email). The four rules:

| Rule | Severity | Fires on |
| --- | --- | --- |
| Brute-force detected | critical | Any `event_action="brute_force_detected"` in 5 min |
| Root login over SSH | high | Any successful root SSH login in 10 min |
| ≥10 failed logins from one IP | high | Per-IP failure spike in 5 min |
| Host stopped reporting | medium | Was active in last 1h, silent for 10 min |

### 6. Verify

From any machine that can reach Loki and Grafana:

```bash
LOKI_URL=https://loki.yourdomain GRAFANA_URL=https://grafana.yourdomain ./verify.sh
```

Expected output ends in `✅ Pipeline healthy`. If not, the script tells you which
step broke.

---

## Architecture

```
┌──────────┐    ┌──────────┐    ┌───────┐    ┌──────┐    ┌─────────┐
│PAMSignal │──▶│ journald │──▶│ Alloy │──▶│ Loki │──▶│ Grafana │
│ (per host)│    │ (per host) │  │(per host)│ │      │    │         │
└──────────┘    └──────────┘    └───────┘    └──────┘    └─────────┘
                                                                ▲
                                                                │
                                                            operator
```

**Why this shape:**

- PAMSignal already writes ECS-aligned structured fields to journald
  (`EVENT_ACTION`, `SOURCE_IP`, `USER_NAME`, ...). No daemon changes required.
- Alloy reads journald with `format_as_json=true`, lowercasing each field
  into `__journal_<field>`, and a relabel pass promotes exactly four to Loki
  labels (`app`, `host`, `service`, `event_action`). Everything else stays
  in the JSON line body and is parsed at query time. See the
  [label cardinality plan](../../docs/grafana-integration.md#label-cardinality-plan).
- Loki indexes those four labels — `5 services × 6 actions × fleet_size`
  streams. Safe to thousands of hosts.

---

## Troubleshooting

### Loki labels not showing up

Run `verify.sh --loki-only` first to isolate Alloy. If the probe event arrives
in Loki with the right labels, the problem is in Alloy's relabel pass.

Check `__journal_*` field names. Journald lowercases custom field names from
`SERVICE_NAME` to `__journal_service_name`. If you see a label name mismatch,
the relabel rule in `alloy.river` won't match.

### Dashboard panels empty

Look at the time picker. The default is "last 6h" — if your stack just came up,
shorten to "last 5m".

Open Grafana **Explore** with the Loki datasource and run `{app="pamsignal"}`.
If no results, data isn't reaching Loki. Check `alloy` and `loki` logs.

### Alloy can't read journald

```
err="open /run/log/journal: permission denied"
```

The `alloy` user must be in the `systemd-journal` group, OR the unit must run
with `Group=systemd-journal`. The packaged unit covers the first case as long
as you ran `usermod -aG systemd-journal alloy`.

### `service_name` label appears alongside `service`

Loki 3.x auto-derives `service_name` for log-volume tracking. Harmless — the
dashboard queries `service=` directly. If you want it gone, set
`discover_log_levels: false` and `discover_service_name: false` in your
`loki.write` block.

### Brute-force panel shows 0 but I know there were brute-force events

PAMSignal only writes `EVENT_ACTION=brute_force_detected` when its internal
`fail_threshold` is hit. If you've tuned that high (e.g., 50), individual hosts
won't trigger and the panel stays at 0. Rule #3 in `alerts.yaml` is the safety
net for this case — it fires on raw failed-login spikes even if PAMSignal
hasn't escalated.

---

## Tuning notes

- **Retention.** Default in `config/loki-config.yml` is 7 days. Increase for
  audit/compliance — see Loki's [retention docs](https://grafana.com/docs/loki/latest/operations/storage/retention/).
- **Cardinality.** Don't promote `source_ip` or `user_name` to Loki labels.
  Both are unbounded and will explode the index. The dashboard parses them at
  query time with `| json` — keep it that way.
- **session_closed noise.** Heavy sudo/su use generates a lot of `session_closed`
  events. There's a commented-out `stage.drop` in `alloy.river` if you want to
  drop them at the Alloy layer.
- **Off-hours alerts.** Not shipped — policy varies. Bolt on a rule with a
  CRON-like filter via Grafana's time-of-day pre-condition if you want one.

---

## Submitting changes

PRs welcome:

- New panels — add to `dashboards/pamsignal-v1.json`, screenshot the change.
- New alert rules — add to `alerts.yaml` with a row in the table above.
- Distro-specific Alloy install notes — append to the "Deploy for real" section.

CI (`.github/workflows/grafana-integration.yml`) brings up the docker-compose
stack on every PR that touches this directory and runs `verify.sh`.

---

## Related links

- [Grafana Alloy](https://grafana.com/docs/alloy/latest/)
- [Loki LogQL](https://grafana.com/docs/loki/latest/logql/)
- [PAMSignal main README](../../README.md)
- [Design doc](../../docs/grafana-integration.md)
