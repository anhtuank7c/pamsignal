# Architecture

PAMSignal is designed around one principle: **do one thing well with minimal moving parts.**

It subscribes to the systemd journal, filters for PAM-related messages from sshd, sudo, su, and login, parses each message to extract structured data (username, source IP, port, service, auth method), and writes structured events back to the journal with custom fields. It tracks failed login attempts per IP and detects brute-force patterns. Optionally, it sends best-effort alerts to messaging platforms without risking the core monitoring.

Single binary. Single config file. Single dependency (`libsystemd`). No database, no web server, no separate relay process.

## C4 Model

### Level 1: System Context

How PAMSignal fits into a Linux server environment.

```mermaid
graph LR
    admin["🧑‍💻 System Administrator"]
    sshd["sshd / sudo / su"]
    journald[("systemd-journald")]
    pamsignal["PAMSignal"]
    platforms["Telegram / Slack / Teams<br/>WhatsApp / Discord"]

    sshd -- "writes PAM auth events" --> journald
    pamsignal -- "reads PAM events" --> journald
    pamsignal -- "writes structured events<br/>via sd_journal_send" --> journald
    pamsignal -. "fork+exec curl<br/>(best-effort)" .-> platforms
    admin -- "journalctl -t pamsignal" --> journald
    platforms -. "receives alerts" .-> admin

    style pamsignal fill:#2d6a4f,stroke:#1b4332,color:#fff
    style journald fill:#264653,stroke:#1d3557,color:#fff
    style sshd fill:#6c757d,stroke:#495057,color:#fff
    style platforms fill:#6c757d,stroke:#495057,color:#fff,stroke-dasharray: 5 5
    style admin fill:#e9c46a,stroke:#f4a261,color:#000
```

### Level 2: Container

PAMSignal is a single-process daemon. Alerts are sent by short-lived child processes that cannot affect the parent.

```mermaid
graph TB
    admin["🧑‍💻 System Administrator"]

    subgraph server ["Linux Server"]
        pam_services["sshd / sudo / su<br/><i>PAM services</i>"]
        journald[("systemd journal<br/><i>structured binary log</i>")]
        pamsignal["PAMSignal Daemon<br/><i>C / libsystemd</i>"]
        systemd["systemd<br/><i>service manager</i>"]
        curl["curl child process<br/><i>short-lived, fire-and-forget</i>"]
    end

    subgraph external ["External (optional)"]
        platforms["Telegram / Slack / Teams<br/>WhatsApp / Discord"]
    end

    pam_services -- "writes auth events" --> journald
    pamsignal -- "reads PAM events &<br/>writes structured events" --> journald
    systemd -- "starts, stops, sandboxes" --> pamsignal
    admin -- "journalctl -t pamsignal" --> journald
    pamsignal -. "fork()" .-> curl
    curl -. "exec curl → HTTP POST" .-> platforms

    style pamsignal fill:#2d6a4f,stroke:#1b4332,color:#fff
    style journald fill:#264653,stroke:#1d3557,color:#fff
    style systemd fill:#6c757d,stroke:#495057,color:#fff
    style pam_services fill:#6c757d,stroke:#495057,color:#fff
    style curl fill:#6c757d,stroke:#495057,color:#fff,stroke-dasharray: 5 5
    style platforms fill:#6c757d,stroke:#495057,color:#fff,stroke-dasharray: 5 5
    style admin fill:#e9c46a,stroke:#f4a261,color:#000
    style server fill:#f8f9fa,stroke:#adb5bd,color:#000
    style external fill:#f8f9fa,stroke:#adb5bd,color:#000
```

### Level 3: Component

```mermaid
graph TB
    journald[("systemd journal")]
    platforms["Telegram / Slack / Teams<br/>WhatsApp / Discord"]

    subgraph daemon ["PAMSignal Daemon"]
        main["<b>main.c</b><br/>CLI parsing, root rejection<br/>journal group check, daemon lifecycle"]
        config["<b>config.c</b><br/>INI parser, validation<br/>SIGHUP reload support"]
        init["<b>init.c</b><br/>Double-fork daemonization<br/>signal handling, PID file"]
        jw["<b>journal_watch.c</b><br/>Journal subscription, event loop<br/>brute-force tracking, alert dispatch"]
        utils["<b>utils.c</b><br/>PAM message parsing<br/>IP validation, log sanitization"]
        notify["<b>notify.c</b><br/>fork+exec curl<br/>fire-and-forget, best-effort"]
    end

    main -- "loads config" --> config
    main -- "initializes" --> init
    main -- "starts event loop" --> jw
    jw -- "parses each entry" --> utils
    jw -- "reloads on SIGHUP" --> config
    jw -- "sd_journal_wait / next<br/>(reads PAM events)" --> journald
    jw -- "sd_journal_send<br/>(writes structured events)" --> journald
    jw -- "on event" --> notify
    notify -. "fork+exec curl" .-> platforms
    init -. "SIGTERM/SIGINT →<br/>running = false" .-> main
    init -. "SIGHUP →<br/>reload_requested = true" .-> jw

    style main fill:#2d6a4f,stroke:#1b4332,color:#fff
    style config fill:#2d6a4f,stroke:#1b4332,color:#fff
    style init fill:#2d6a4f,stroke:#1b4332,color:#fff
    style jw fill:#2d6a4f,stroke:#1b4332,color:#fff
    style utils fill:#2d6a4f,stroke:#1b4332,color:#fff
    style notify fill:#2d6a4f,stroke:#1b4332,color:#fff
    style journald fill:#264653,stroke:#1d3557,color:#fff
    style platforms fill:#6c757d,stroke:#495057,color:#fff,stroke-dasharray: 5 5
    style daemon fill:#f8f9fa,stroke:#adb5bd,color:#000
```

## Data flow

```
SSH login attempt
    → sshd writes to journald
        → pamsignal reads via sd_journal_wait/next
            → utils.c parses message, extracts fields
                → journal_watch.c writes structured event via sd_journal_send
                    → journald stores event with custom PAMSIGNAL_* fields
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
