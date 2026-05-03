# Architecture

PAMSignal is designed around one core principle: **do one thing well with minimal moving parts.**

It subscribes to the systemd journal, filters for PAM-related messages from sshd, sudo, su, and login, parses each message to extract structured data (username, source IP, port, service, auth method), and writes structured events back to the journal with custom fields. It tracks failed login attempts per IP and detects brute-force patterns. Optionally, it sends best-effort alerts to messaging platforms without risking the core monitoring.

Single binary. Single config file. Single dependency (`libsystemd`). No database, no web server, no separate relay process.

## C4 Model

Following the [C4 model](https://c4model.com/) conventions, we map out the architecture from a high-level system context down to internal components.

### Level 1: System Context

The System Context diagram provides a high-level overview of how users interact with internal and external systems to get value. It shows PAMSignal within the larger Linux server environment.

```mermaid
C4Context
  title System Context diagram for PAMSignal

  Person(admin, "System Administrator", "A sysadmin who monitors and secures the server")
  
  System(pamsignal, "PAMSignal", "Real-time PAM event monitor and alert dispatcher")
  
  System_Ext(sshd, "PAM Services", "sshd, sudo, su, login")
  System_Ext(journald, "systemd-journald", "Centralized binary logging system")
  System_Ext(platforms, "Messaging Platforms", "Telegram, Slack, Teams, WhatsApp, Discord, Webhooks")
  System_Ext(fail2ban, "Fail2ban", "Intrusion prevention system (iptables / ufw)")

  Rel(sshd, journald, "Writes PAM auth events to")
  Rel(pamsignal, journald, "Reads PAM events & writes structured alerts to")
  Rel(admin, journald, "Queries structured events via journalctl")
  Rel(pamsignal, platforms, "Dispatches alerts via curl", "HTTPS")
  Rel(platforms, admin, "Delivers alert messages to")
  Rel(fail2ban, journald, "Watches for pamsignal BRUTE_FORCE_DETECTED events")
```

### Level 2: Container

The Container diagram zooms into the system boundary to show the separately runnable/deployable containers. PAMSignal is a single-process daemon. Alerts are sent by short-lived child processes (`curl`) that cannot affect the parent monitoring daemon.

```mermaid
C4Container
  title Container diagram for PAMSignal
  
  Person(admin, "System Administrator", "A sysadmin who monitors the server")
  
  System_Boundary(server, "Linux Server") {
      System_Ext(sshd, "PAM Services", "sshd, sudo, su, login")
      System_Ext(journald, "systemd-journald", "Structured binary log")
      System_Ext(systemd, "systemd", "Service manager")
      System_Ext(fail2ban, "Fail2ban", "Intrusion prevention framework")
      
      Container(daemon, "PAMSignal Daemon", "C / libsystemd", "Core monitoring process running as an unprivileged service")
      Container(curl, "curl Child Process", "cURL", "Short-lived fire-and-forget alert dispatcher")
  }
  
  System_Ext(platforms, "External Platforms", "Telegram, Slack, Teams, WhatsApp, Discord, Webhook")

  Rel(sshd, journald, "Writes auth events to")
  Rel(daemon, journald, "Reads events & writes structured alerts to")
  Rel(systemd, daemon, "Starts, stops, sandboxes")
  Rel(admin, journald, "Queries logs via journalctl")
  Rel(daemon, curl, "fork() & exec()", "Process creation")
  Rel(curl, platforms, "POSTs JSON/text alerts to", "HTTPS")
  Rel(fail2ban, journald, "Watches BRUTE_FORCE_DETECTED events")
```

### Level 3: Component

The Component diagram zooms into the PAMSignal daemon container to show its internal C components, mapping to the actual source files in the project.

```mermaid
C4Component
  title Component diagram for PAMSignal Daemon
  
  Container_Ext(journald, "systemd-journald", "System log service")
  Container_Ext(curl, "curl Child Process", "cURL binary")

  Container_Boundary(daemon, "PAMSignal Daemon") {
      Component(main, "main.c", "C", "CLI parsing, root rejection, journal group check, daemon lifecycle")
      Component(config, "config.c", "C", "INI parser, validation, SIGHUP reload support")
      Component(init, "init.c", "C", "Double-fork daemonization, signal handling, PID file")
      Component(jw, "journal_watch.c", "C", "Journal subscription, event loop, brute-force state tracking")
      Component(utils, "utils.c", "C", "PAM message parsing, IP validation, log sanitization")
      Component(notify, "notify.c", "C", "Alert formatting and fork+exec dispatch")
  }

  Rel(main, config, "Loads config using")
  Rel(main, init, "Initializes daemon using")
  Rel(main, jw, "Starts event loop in")
  Rel(jw, utils, "Parses messages using")
  Rel(jw, config, "Reloads on SIGHUP using")
  
  Rel(jw, journald, "Reads PAM events & writes structured alerts via sd_journal_send")
  Rel(jw, notify, "Triggers alerts via")
  Rel(notify, curl, "fork+exec() (fire-and-forget)")
```

## Data flow

```
SSH login attempt
    → sshd writes to journald
        → pamsignal reads via sd_journal_wait/next
            → utils.c parses message, extracts fields
                → journal_watch.c writes structured event via sd_journal_send
                    → journald stores event with custom fields
                        → admin reads with: journalctl -t pamsignal
                → notify.c fork() → child exec("curl", ...) → Telegram/Slack/etc.
                    → parent continues immediately (fire-and-forget)
                    → child exits on its own (success or failure)
```

## Alert isolation model

Alerts are **best-effort and cannot break the core monitoring**. Here's how:

```mermaid
graph LR
    subgraph parent ["PAMSignal (parent process)"]
        event["Event detected"]
        write_journal["Write to journal"]
        do_fork["fork()"]
        continue["Continue event loop"]
    end

    subgraph child ["Child process (short-lived)"]
        exec_curl["exec curl"]
        send["HTTP POST"]
        exit_child["exit"]
    end

    event --> write_journal
    write_journal --> do_fork
    do_fork --> continue
    do_fork -. "child" .-> exec_curl
    exec_curl --> send
    send --> exit_child

    style parent fill:#f8f9fa,stroke:#2d6a4f,color:#000
    style child fill:#f8f9fa,stroke:#7f5539,color:#000,stroke-dasharray: 5 5
    style event fill:#2d6a4f,stroke:#1b4332,color:#fff
    style write_journal fill:#2d6a4f,stroke:#1b4332,color:#fff
    style do_fork fill:#2d6a4f,stroke:#1b4332,color:#fff
    style continue fill:#2d6a4f,stroke:#1b4332,color:#fff
    style exec_curl fill:#7f5539,stroke:#6c584c,color:#fff
    style send fill:#7f5539,stroke:#6c584c,color:#fff
    style exit_child fill:#7f5539,stroke:#6c584c,color:#fff
```

**Why this is safe:**

1. The parent **always writes to the journal first** — the core record is persisted before any alert attempt
2. `fork()` creates a copy-on-write child — cheap on Linux, no shared state
3. The parent **does not wait** for the child — it continues the event loop immediately
4. If the child crashes, segfaults, or hangs — the parent is completely unaffected
5. If Telegram/Slack/Discord is down — the child times out and exits, pamsignal keeps monitoring
6. `SIGCHLD` is ignored (`SA_NOCLDWAIT`) so zombie processes are automatically reaped
7. The child `exec`s `curl` — no HTTP library linked into the parent process at all

## Structured journal fields

PAMSignal writes events using `sd_journal_send()` with custom fields that both humans and machines can read:

| Field | Example | Description |
|-------|---------|-------------|
| `PAMSIGNAL_EVENT` | `LOGIN_FAILED` | Event type |
| `PAMSIGNAL_USERNAME` | `root` | Username from PAM message |
| `PAMSIGNAL_SOURCE_IP` | `203.0.113.45` | Remote IP (validated) |
| `PAMSIGNAL_PORT` | `22` | Remote port |
| `PAMSIGNAL_SERVICE` | `sshd` | PAM service |
| `PAMSIGNAL_AUTH_METHOD` | `password` | Auth method |
| `PAMSIGNAL_HOSTNAME` | `web-01` | Server hostname |

For brute-force events:

| Field | Example | Description |
|-------|---------|-------------|
| `PAMSIGNAL_EVENT` | `BRUTE_FORCE_DETECTED` | Event type |
| `PAMSIGNAL_SOURCE_IP` | `203.0.113.45` | Offending IP |
| `PAMSIGNAL_ATTEMPTS` | `5` | Number of failed attempts |
| `PAMSIGNAL_WINDOW_SEC` | `300` | Time window |
| `PAMSIGNAL_USERNAME` | `root` | Last username attempted |

Query examples:

```bash
# All pamsignal events
journalctl -t pamsignal

# Only failed logins
journalctl -t pamsignal PAMSIGNAL_EVENT=LOGIN_FAILED

# Only brute-force alerts
journalctl -t pamsignal PAMSIGNAL_EVENT=BRUTE_FORCE_DETECTED

# Events from a specific IP
journalctl -t pamsignal PAMSIGNAL_SOURCE_IP=203.0.113.45

# JSON output (for scripting)
journalctl -t pamsignal -o json
```

## Design decisions

**Why systemd journal as the primary output?**
The journal is already there. It provides structured fields, access control, persistence, and rotation. Administrators can query with `journalctl` filters. Scripts can consume JSON output. No custom log format to maintain.

**Why fork+exec curl for alerts (not libcurl, not a separate relay)?**
Three concerns balanced:
- **Usability:** One binary, one config file. No Python, no pip, no second service to manage.
- **Isolation:** Child process crash cannot affect the parent. No HTTP library in the parent's address space.
- **Simplicity:** `curl` is pre-installed on every Linux server. No new dependency to compile or link.

A separate relay (journal subscriber in Python) is the architecturally purest approach but doubles the operational complexity. Fork+exec achieves the same fault isolation with zero user-facing complexity.

**Why non-root?**
The daemon only needs to read the journal. Running as root would widen the attack surface for zero benefit. The `systemd-journal` group grants read access.

**Why a static fail table (not a hash map)?**
The table is bounded at `max_tracked_ips` entries (default 256). A flat array with linear scan is simpler, has no allocator overhead, and is fast enough for this scale. If you're tracking 100,000 IPs, you need a different tool.

**Why INI config (not YAML/JSON)?**
Zero dependencies. The config has ~10 keys — YAML/JSON parsing libraries add complexity for no benefit. Sysadmins can edit it with `vi` in 10 seconds.

**Why no network code in the parent process?**
Every network dependency (libcurl, sockets, TLS) is an attack surface. A security monitoring tool should minimize its own attack surface. The parent reads from the journal, writes to the journal, and forks children for alerts. The children exec `curl` and exit. The parent never makes a network call.
