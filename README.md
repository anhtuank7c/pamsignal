# PAMSignal

![License](https://img.shields.io/github/license/anhtuank7c/pamsignal)
![Language](https://img.shields.io/badge/Language-C-orange)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)

## Introduction

System administrators are often reactive to unauthorized intrusions because default logging systems are difficult to monitor, easily tampered with, or existing security tools are too heavy and complex to deploy on low-spec servers. Or perhaps you simply don't have the budget or manpower to implement massive systems like EDR (**E**ndpoint **D**etection and **R**esponse) or XDR (**E**xtended **D**etection and **R**esponse), which are designed for large, professional enterprises.

**Why I created PAMSignal**

- I manage a number of Linux servers with **limited resources** and needed a lightweight monitoring tool that didn't exist in the way I wanted.
- I wanted to deepen my understanding of C, Linux internals, and security — skills that remain in demand even as the industry shifts.
- I wanted to connect with and learn from industry experts.
- I wanted to create an open-source product Made in Vietnam.

**On using AI in this project**

This project is built with AI assistance ([Claude Code](https://claude.ai/claude-code)). I review, test, and take responsibility for every line that gets merged.

Why? The honest answer: time. The tech job market since 2023 has been brutal — [mass layoffs](https://layoffs.fyi/), hiring freezes, and a shift toward fewer engineers expected to do more. Meanwhile AI coding tools have moved from autocomplete to genuine pair programming. Ignoring that is not pragmatism, it's denial.

I don't treat AI as a replacement for understanding. I treat it as a force multiplier: it handles boilerplate, catches patterns I'd miss at 2 AM, and lets me ship a real project while holding down a day job and other responsibilities. Every architectural decision, every security review, every commit message — I read it, I verify it, I own it.

This is the new reality for independent developers: use the tools available, apply them with care, and spend your limited hours on the problems that actually need a human.

**What is PAMSignal?**

PAMSignal is a Linux-specific application for monitoring and alerting immediately when login sessions occur. It ensures you're always proactive in every situation.

**Who needs PAMSignal?**

Many people ask me: Why not use **Wazuh** or install **EDR**, **XDR** for a more professional solution?

The simple answer is: **Don't use a sledgehammer to crack a nut.**

So who is **PAMSignal** suitable for?

PAMSignal focuses on Access Monitoring, so you'll need PAMSignal if:

- You need to manage 1-10 Linux VPS/servers (or more).
- You have minimal server specs but still want monitoring.
- You need an access monitoring tool that's simple enough, lightweight, with no backend required.
- You prioritize minimalism, plug & play installation, without spending time reading hundreds of pages of documentation.
- You need a tool that can send alerts to Telegram/Slack/custom webhooks (integrate directly into your web application).
- You need a free tool, distributed under the [MIT open-source license](./LICENSE).

**Why use C as the primary programming language for PAMSignal?**

PAMSignal is written in pure C to ensure no dependency on bulky runtimes (like Python or Java), minimizing the attack surface for itself, and simplifying the installation process while keeping the installation footprint minimal.

## Development Guide

### Prerequisites

```bash
sudo apt install libsystemd-dev pkg-config build-essential meson ninja-build
```

### Build

```bash
# First time: configure the build directory
meson setup build

# Compile
meson compile -C build
```

### Clean

```bash
# Remove all build artifacts and reconfigure
rm -rf build
meson setup build
```

### Setup test environment

PAMSignal runs as a dedicated unprivileged user with journal read access (not root).

```bash
# Create a system user for pamsignal (no login shell, no home directory)
sudo useradd -r -s /usr/sbin/nologin pamsignal

# Grant permission to read the systemd journal
sudo usermod -aG systemd-journal pamsignal
```

You also need SSH available locally to generate real login events:

```bash
sudo apt install openssh-server
sudo systemctl enable --now ssh
```

### Run (manual)

```bash
# Foreground mode (Ctrl+C to stop)
sudo -u pamsignal ./build/pamsignal --foreground

# Or as a background daemon
sudo -u pamsignal ./build/pamsignal
```

### Run (systemd service)

```bash
# Install binary and service file
sudo meson install -C build

# Reload systemd and start the service
sudo systemctl daemon-reload
sudo systemctl enable --now pamsignal

# Check status
sudo systemctl status pamsignal

# View logs
journalctl -u pamsignal -f
```

### Stop

```bash
# If running as systemd service
sudo systemctl stop pamsignal

# If running manually as background daemon
sudo kill $(pgrep pamsignal)
```

### End-to-end testing

Start pamsignal and open a second terminal to watch its output:

```bash
journalctl -t pamsignal -f
```

Then in a third terminal, trigger events:

```bash
# 1. Successful SSH login (expect: LOGIN_SUCCESS + SESSION_OPEN)
ssh localhost
# type 'exit' (expect: SESSION_CLOSE)

# 2. Failed SSH login (expect: LOGIN_FAILED)
ssh nonexistent@localhost

# 3. Brute-force detection (expect: BRUTE_FORCE_DETECTED after 5 failures)
for i in $(seq 1 5); do ssh nonexistent@localhost; done

# 4. Sudo session (expect: SESSION_OPEN for sudo)
sudo ls

# 5. Graceful shutdown (expect: "shutting down" in journal)
sudo systemctl stop pamsignal
# or Ctrl+C if running in foreground
```

## Project Roadmap

### Phase 1: The Core Observer (done)

- [x] [Initialize: C project structure, dependency management with Meson.](./docs/phase-1-initialize.md)
- [x] [Journal Subscriber: Use **libsystemd** to listen to auth event streams.](./docs/phase-1-systemd-jounald.md)
- [x] **PAM Logic:** Filter *session opened* and *session closed* events.
- [x] **Information Extractor:** Extract user, remote IP, service (sshd/sudo/su), timestamp, and authentication method (password/key).
- [x] **Failed Login Tracking:** Monitor and count failed authentication attempts for brute-force detection.
- [x] **Signal Handling:** SIGTERM/SIGINT handling for clean shutdown.
- [x] **Systemd Service:** Service file with security hardening (`ProtectSystem=strict`, `NoNewPrivileges=yes`, `MemoryDenyWriteExecute=yes`).
- [x] **Build Hardening:** Stack protector, FORTIFY_SOURCE, PIE, full RELRO, format-security.

### Phase 2: Alerts & Configuration

- [ ] **Multi-channel Alert:** Integrate `libcurl` for Telegram/Slack/webhook notifications.
- [ ] **Config Manager:** Configuration file (YAML or JSON) with validation and sane defaults.
- [ ] **Message Templating:** Design professional, easy-to-read notification structure.
- [ ] **SIGHUP Config Reload:** Reload configuration without restarting the daemon.
- [ ] **Rate Limiting:** Configurable alert throttling to prevent notification flooding during attacks.

### Phase 3: Context Awareness

- [ ] **Network Discovery:** Query `/proc/net/tcp` and `/proc/net/tcp6` to identify destination IP and support IPv6.
- [ ] **Provider Identity:** Identify cloud providers (AWS, GCP, DigitalOcean, etc.).
- [ ] **ASN/Organization Lookup:** Get the ISP/organization of the accessor using offline GeoIP database (MaxMind GeoLite2).
- [ ] **FHS Compliance:** Binary in `/usr/bin`, configuration in `/etc/pamsignal`, logs in `/var/log/pamsignal`.

### Phase 4: Enterprise & Distribution

- [ ] **SIEM Integration:** Forward events to remote syslog/SIEM systems (CEF/LEEF format).
- [ ] **Log Integrity:** SHA256 hashing of alert records to prevent tampering.
- [ ] **Health Monitoring:** Systemd watchdog integration and metrics for failed deliveries/processing lag.
- [ ] **Graceful Degradation:** Handle systemd journal unavailability without crashing.
- [ ] **Audit Trail:** Configurable log retention policies for compliance (NIST 800-53, CIS Controls).
- [ ] **Package Building:** Native `.deb` and `.rpm` packages with GPG signing.
- [ ] **Repository Distribution:** GitHub Releases, Debian PPA, and Fedora COPR.
- [ ] **Documentation:** Man pages (`pamsignal(8)`, `pamsignal.conf(5)`) and installation guides.
- [ ] **Automated Testing:** Unit tests, integration tests, security fuzzing, and multi-distro package tests.
- [ ] **CI/CD Pipeline:** GitHub Actions for building, testing, signing, and publishing across distributions.
