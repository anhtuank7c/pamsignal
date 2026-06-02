# Use Cases & Integrations

> 🌐 **English** · [Tiếng Việt](vi/use-cases.md)

PAMSignal is deliberately small. It does **one** job — watch PAM authentication events and tell you about them — and it speaks open, standard formats (structured journal entries and [ECS](https://www.elastic.co/guide/en/ecs/current/index.html) JSON) so it slots into whatever you already run instead of becoming yet another console to babysit.

This page answers two questions: **who gets value from PAMSignal**, and **how do you fit it into an existing stack**.

> **Scope reminder.** PAMSignal is the *detection and alerting* layer. It does not prevent logins, block IPs, scan files, or replace a SOC. It pairs with the tools that do those jobs — see [Secure SSH](./ssh-hardening.md) (prevention), [Fail2ban](../examples/fail2ban/README.md) (response), and the [Threat Model](./threat-model.md) for exactly what it can and cannot see.

---

## Who PAMSignal is for

### Solo developer / self-hoster

You run 1–5 personal VPSes, a homelab, or a side project. You don't want to deploy Wazuh or read 200 pages of EDR docs — you just want to **know the moment someone logs into your box, or starts trying to**.

**A good setup:**
- Install via the [Quick Start](../README.md#-quick-start) one-liner.
- Add a [Telegram](./alerts.md#telegram) or [Discord](./alerts.md) channel — done in two minutes.
- Set `enable_notification_type = login_success,brute_force` so you're pinged about successful logins and attacks, not every event.
- Optionally add [Fail2ban](../examples/fail2ban/README.md) to auto-ban brute-forcers.

**What you get:** a phone buzz when you (or anyone) logs in successfully, and when a bot starts hammering you. That's 90% of the peace-of-mind for 0% of the operational weight.

### Small team / startup ops

You run 5–30 servers, share an on-call rotation, and already have a Slack or Teams workspace.

**A good setup:**
- Roll out across the fleet with the [Ansible playbook](./ssh-hardening.md#32-the-repeatable-way-ansible), one shared `pamsignal.conf`.
- Route alerts to a dedicated **#security-alerts** [Slack/Teams](./alerts.md) channel.
- Stand up the [Grafana fleet dashboard](./grafana-getting-started.md) so anyone on-call sees the whole fleet at a glance.
- If you already run a SIEM, also forward events there via the [custom webhook](#already-run-a-siem-elastic--wazuh--splunk--datadog).

**What you get:** the team shares one real-time feed and one fleet-wide dashboard; nobody is grepping `journalctl` on individual hosts during an incident.

### Small hosting provider / MSP

You run servers *for other people* — shared hosting, VPS resale, managed dedicated boxes, or a managed-service contract. Auth visibility is something your customers want but rarely build themselves, and PAMSignal lets you offer it as a **value-add at near-zero cost**: it's a single small C binary depending only on `libsystemd`, alerts via short-lived `fork+exec curl`, and adds no measurable load to a customer VPS. You can put it on every box you manage.

Here's the full playbook.

#### 1. Tag every host so alerts self-identify

Set the two context-tag keys in each host's `pamsignal.conf` (template them per-host with [Ansible](./ssh-hardening.md#32-the-repeatable-way-ansible)):

```ini
provider = acme-cloud
service_name = cust-1042-web01
```

Every alert and webhook payload now carries `provider=acme-cloud service_name=cust-1042-web01`, so you always know *which customer and which box* an alert came from — even when they all land in one place. (See [Alerts](./alerts.md#message-format).)

#### 2. Choose your alert-routing model

PAMSignal config is **per host**, which gives you two clean options:

- **Direct-to-customer.** Put the customer's own Telegram/Slack credentials in *their* hosts' configs. Each customer is alerted about their own servers directly — a tangible feature they can see working.
- **NOC-centric.** Send every host to your operations channel / webhook, and give customers a read-only [Grafana](./grafana-getting-started.md) view (next). Better when *you* are the one responding.

You can mix: customer-facing pings for successes/brute-force, full firehose to your NOC.

#### 3. Give each customer their own dashboard view

Grafana is built for multi-tenancy. Pick the isolation level that matches your business:

- **Per-customer dashboard / folder**, with the `$host` variable locked to that customer's hosts — simplest, fine when customers don't log in themselves.
- **A Grafana Organization (or Grafana RBAC team) per tenant** — real isolation; give the customer a scoped, read-only login so they only ever see their own hosts.

Because the host name and your `service_name` tag are already labels/fields, scoping a view to one customer is a filter, not a data-separation project.

#### 4. Surface it in your own portal (white-label)

Point the [custom webhook](./configuration.md#custom-webhook-authentication) at your control-panel backend. PAMSignal POSTs [ECS JSON](./alerts.md#custom-webhook-ecs-json) for every event; your backend stores it and renders a "**Recent logins & blocked attacks**" widget right inside the customer's existing dashboard — fully your branding. The [Node.js](../examples/nodejs-webhook/README.md) and [Python](../examples/python-webhook/README.md) webhook examples are working receivers you can build on.

#### 5. Package it as a tier

- **Free / included:** real-time brute-force + root-login alerts to the customer.
- **Paid add-on:** the fleet dashboard, 90-day (or 1-year) [audit retention](./grafana-getting-started.md#costs--cautions) in Loki, and a monthly "auth activity & blocked attacks" report. The data is already flowing; the tier is packaging.

#### 6. Know — and state — the boundaries

Be honest with customers about what this is, so it stays a feature and never a liability:

- It covers the **PAM-stack channels** — SSH, sftp, sudo, su, console login. It does **not** see VPN, cloud-provider web consoles, control-panel logins, or container exec. ([Threat Model — Observation scope](./threat-model.md#observation-scope).)
- It is **detection and alerting**, not a managed SOC, not antivirus/EDR, not a WAF.
- Position it accurately: *"We alert you in seconds about SSH logins and brute-force attacks on your server, and keep a searchable history."* That is true, valuable, and defensible — and for customers who need a real SOC, it's a clean first layer to build on.

### Compliance-minded shops

If you need to *show* who logged in and when, the [Grafana + Loki](./grafana-getting-started.md) path gives you a retained, searchable, timestamped auth trail across the fleet, and the [custom webhook](#already-run-a-siem-elastic--wazuh--splunk--datadog) feeds the same events into a SIEM of record. PAMSignal is the sensor; your retention policy turns it into an audit trail.

---

## Plug it into your existing stack

PAMSignal is a **sensor**, not a destination. It emits in two open formats — single-line `key=value` text for chat, and nested [ECS JSON](./alerts.md#custom-webhook-ecs-json) for machines — so it feeds tools you already run rather than replacing them.

| If you already run… | Wire it up with… | Result |
|---|---|---|
| Slack / Teams / Discord / Telegram / WhatsApp | Native channels — just add credentials | Real-time alerts in your existing chat |
| A SIEM (Elastic, Wazuh, Splunk, Datadog) | `webhook_url` → ECS JSON | Events drop in with no field remapping |
| Grafana + Loki | Alloy scrape | [Fleet-wide auth dashboard](./grafana-getting-started.md) |
| Fail2ban / CrowdSec | The `brute_force_detected` journal signal | Automatic IP blocking at the firewall |
| Ansible / Salt / Puppet | Package + config template | [Reproducible fleet rollout](./ssh-hardening.md#part-3--roll-pamsignal-out-across-the-fleet) |
| PagerDuty / Opsgenie | Grafana contact point, or webhook | On-call paging on the rules that matter |
| Your own app / portal | `webhook_url` → your endpoint | Anything — see the [webhook examples](../examples/nodejs-webhook/README.md) |

### Already use chat (Slack / Teams / Discord / Telegram / WhatsApp)?

This is the zero-effort path. Drop the channel's credentials into `pamsignal.conf` and you're done — PAMSignal sends to every channel that has credentials set. Setup per channel is in [Alerts](./alerts.md). Narrow the noise with [`enable_notification_type`](./configuration.md#notification-type-filter).

### Already run a SIEM (Elastic / Wazuh / Splunk / Datadog)?

Point `webhook_url` at your ingest endpoint. PAMSignal POSTs an [ECS](https://www.elastic.co/guide/en/ecs/current/index.html)-structured JSON document per event — nested `event.*`, `host.*`, `user.*`, `source.*`, `service.*`, `process.*` objects plus a `pamsignal.*` namespace — which "drops directly into Elastic SIEM and Wazuh without remapping, and is one Vector/Logstash config away from any other modern SIEM." Authenticate with a [bearer header or mTLS](./configuration.md#custom-webhook-authentication):

```ini
webhook_url = https://siem.example.com/ingest/pamsignal
webhook_auth_header = Authorization: Bearer <token>
```

The on-the-wire payload and a receiver-pattern table (Splunk HEC, Datadog, X-API-Key, Wazuh) are in [Alerts → Custom webhook](./alerts.md#custom-webhook-ecs-json). This is the integration that makes PAMSignal a *source* in a bigger detection pipeline rather than a standalone tool.

### Already run Grafana + Loki?

You're most of the way there — just install [Grafana Alloy](./grafana-getting-started.md#path-a--grafana-cloud-managed-zero-ops) on each host to scrape `SYSLOG_IDENTIFIER=pamsignal` from the journal, and import the bundled dashboard. Full walkthrough: [Grafana from Zero](./grafana-getting-started.md).

### Already run Fail2ban or CrowdSec?

PAMSignal does the counting; let your blocker act on the result. [Fail2ban](../examples/fail2ban/README.md) reads the `BRUTE_FORCE_DETECTED` journal line directly (`journalmatch = SYSLOG_IDENTIFIER=pamsignal`) — no fragile `sshd` regex to maintain. CrowdSec users can point a journald acquisition at the same identifier. PAMSignal observes; the blocker enforces; the two stay fully decoupled.

### Already use config management?

Treat PAMSignal like any other package: install it and template `pamsignal.conf`. The [fleet rollout section](./ssh-hardening.md#part-3--roll-pamsignal-out-across-the-fleet) has a ready Ansible playbook with per-host context tags.

### Want to build your own integration?

The [custom webhook](./configuration.md#custom-webhook-authentication) sends ECS JSON to any URL. Build auto-banning, ticket creation, customer-portal widgets, or anything else. Start from the [Node.js](../examples/nodejs-webhook/README.md) or [Python](../examples/python-webhook/README.md) receiver examples, and use the [Bruno collection](../examples/bruno-collection/README.md) to inspect real payloads.

---

## "Why not just use…?"

PAMSignal isn't trying to be the only thing in your stack — but here's where it fits relative to the usual alternatives:

- **…Wazuh / OSSEC / a full EDR?** Those are excellent and far broader — and far heavier (agents, a manager, a database, tuning). PAMSignal is the right size when you want auth alerting *now* without standing up a platform. They also compose: feed PAMSignal's webhook into Wazuh and use it as a lightweight sensor.
- **…a `tail -f auth.log | grep` script?** Fragile across distros and `sshd` versions, blind to the structured journal, and yours to maintain forever. PAMSignal already understands `sshd`, `sshd-session`, `sudo`, `su`, and `login` formats and emits structured events.
- **…my cloud provider's login alerts?** Those usually cover the *cloud console*, not OS-level SSH/sudo on the instance. PAMSignal watches the host itself — and works identically on bare metal, a VPS, or any cloud.
- **…nothing?** The honest baseline for most small servers. PAMSignal's whole pitch is that it's cheap enough — one binary, one config — that "nothing" is no longer the easy choice.

---

## Further reading

- 🚀 **[Quick Start](../README.md#-quick-start)** — install and first alert
- 🔐 **[Secure SSH & Manage a Fleet](./ssh-hardening.md)** — prevention layer + fleet rollout
- 📊 **[Grafana from Zero](./grafana-getting-started.md)** — the fleet dashboard and multi-tenant patterns
- 🔔 **[Alerts](./alerts.md)** — chat formats and the ECS JSON webhook payload
- ⚙️ **[Configuration](./configuration.md)** — every config key, including webhook auth/mTLS
- 🎯 **[Threat Model](./threat-model.md)** — what PAMSignal defends, and the channels it deliberately doesn't see
