# PAMSignal

![License](https://img.shields.io/github/license/anhtuank7c/pamsignal)
![Language](https://img.shields.io/badge/Language-C-orange)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)

## Introduction

System administrators are often reactive to unauthorized intrusions because default logging systems are difficult to monitor, easily tampered with, or existing security tools are too heavy and complex to deploy on low-spec servers. Or perhaps you simply don't have the budget or manpower to implement massive systems like EDR (**E**ndpoint **D**etection and **R**esponse) or XDR (**E**xtended **D**etection and **R**esponse), which are designed for large, professional enterprises.

**Why I created PAMSignal**

- I personally encountered many challenges and obstacles managing a considerable number of Linux servers with **limited resources**.
- I wanted to practice C programming more and master this skill.
- I wanted to connect with and learn from industry experts.
- I wanted to dive deeper into Linux.
- I wanted to create an open-source product Made in Vietnam.

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

## Project Roadmap

I've divided the project into 4 main phases to ensure feasibility, sustainability, and alignment with Linux security industry standards:

### Phase 1: The Core Observer

- [x] [Initialize: C project structure, dependency management with Makefile.](./docs/phase-1-initialize.md)
- [ ] [Journal Subscriber: Use *libsystemd* to listen to auth event streams.](./docs/phase1-systemd-jounal.md)
- [ ] **PAM Logic:** Accurately filter *session opened* and *session closed* events.
- [ ] **Information Extractor:** Extract comprehensive data fields:
  - User, Remote IP, Service (sshd/sudo/su)
  - Timestamp, session duration, authentication method (password/key)
- [ ] **Failed Login Tracking:** Monitor and count failed authentication attempts for brute-force detection.
- [ ] **Auditd Integration:** Optional support for `pam_tty_audit` to monitor privileged user sessions.
- [ ] **IPv6 Support:** Parse `/proc/net/tcp6` for complete network coverage.

### Phase 2: Context Awareness

- [ ] **Network Discovery:** List all existing IPs on the server.
  - Query `/proc/net/tcp` and `/proc/net/tcp6` to identify **Destination IP** (the IP the client is connecting to).
  - Support for Unix socket authentication tracking.
- [ ] **Provider Identity:** Integrate logic to identify Cloud providers (AWS, GCP, DigitalOcean, etc.).
- [ ] **ASN/Organization Lookup:** Get the ISP name of the accessor (e.g., Viettel, FPT, or a suspicious data center in Russia).
  - Use offline GeoIP database (MaxMind GeoLite2) to avoid external dependencies.
- [ ] **Message Templating:** Design professional, easy-to-read notification structure.
- [ ] **Security Hardening:** Implement comprehensive systemd service isolation:
  - Create dedicated unprivileged user with `DynamicUser=yes`.
  - Apply `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`.
  - Restrict capabilities: `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`.
  - Syscall filtering: `SystemCallFilter=@system-service`.
  - Set `NoNewPrivileges=yes` to prevent privilege escalation.
- [ ] **FHS Compliance:** Follow Filesystem Hierarchy Standard:
  - Binary in `/usr/bin`, configuration in `/etc/pamsignal`, logs in `/var/log/pamsignal`.
  - Proper file permissions: config `0600`, binary `0755`.

### Phase 3: Enterprise Readiness

- [ ] **SIEM Integration:** Forward events to remote syslog/SIEM systems for centralized monitoring.
  - Support CEF (Common Event Format) and LEEF (Log Event Extended Format).
- [ ] **Log Integrity:** Implement SHA256 hashing of alert records to prevent tampering.
- [ ] **Rate Limiting:** Configurable alert throttling to prevent notification flooding during attacks.
- [ ] **Health Monitoring:** 
  - Systemd watchdog integration for service health checks.
  - Expose metrics for failed alert deliveries and processing lag.
- [ ] **Graceful Degradation:** Handle systemd journal unavailability without service crashes.
- [ ] **Signal Handling:** Proper SIGTERM/SIGHUP handling for clean shutdown and configuration reload.
- [ ] **Audit Trail:** Configurable log retention policies for compliance requirements (NIST 800-53, CIS Controls).

### Phase 4: Distribution & Release

- [ ] **Multi-channel Alert:** Integrate `libcurl` to send notifications via Telegram/Slack API.
- [ ] **Config Manager:** Build configuration file (YAML or JSON) with validation:
  - JSON schema for config validation.
  - Comprehensive documentation with sane defaults.
- [ ] **Traditional Package Formats (PRIMARY):** Build native packages for maximum compatibility:
  - **`.deb` packages** for Debian/Ubuntu/Mint (APT):
    - Create `debian/` directory with control files, rules, and changelog.
    - Use `dpkg-buildpackage` or `debuild` for building.
    - Sign packages with GPG for authenticity.
    - Include systemd service unit files and post-install scripts.
  - **`.rpm` packages** for RHEL/Fedora/CentOS/Rocky/AlmaLinux (DNF/YUM):
    - Create `.spec` file with build instructions and dependencies.
    - Use `rpmbuild` for package creation.
    - Sign packages with GPG for authenticity.
    - Include systemd service unit files and post-install scripts.
- [ ] **Repository Distribution:**
  - **Debian/Ubuntu**: Submit to official repositories or create PPA (Personal Package Archive).
  - **Fedora**: Submit to Fedora COPR (Cool Other Package Repo).
  - **GitHub Releases**: Provide direct downloads for `.deb` and `.rpm` files.
  - Create installation scripts for one-line setup (`curl | bash` pattern).
- [ ] **Snap Packages (OPTIONAL):** Universal package for convenience:
  - Create `snapcraft.yaml` with proper confinement settings.
  - Publish to Snap Store as supplementary distribution channel.
  - Note: Snap is secondary due to performance overhead and enterprise resistance.
- [ ] **Documentation:** 
  - Man pages (`pamsignal(8)`, `pamsignal.conf(5)`).
  - Systemd service configuration examples.
  - Installation guides for each distribution family.
  - Repository setup instructions (adding GPG keys, sources.list entries).
- [ ] **Automated Testing:** 
  - Unit tests for core logic (event parsing, filtering).
  - Integration tests with mock systemd journal.
  - Security tests (fuzzing, privilege escalation checks).
  - Performance tests (handle 1000+ logins/sec).
  - Package installation tests on multiple distributions (Ubuntu, Debian, Fedora, RHEL).
- [ ] **CI/CD Pipeline:** GitHub Actions for automated building, testing, and packaging:
  - Multi-distribution build matrix (Ubuntu 22.04/24.04, Debian 11/12, Fedora 39/40, RHEL 9).
  - Automated package signing with GPG.
  - Automated publishing to GitHub Releases.
  - Automated repository updates.
- [ ] **Official Release:** 
  - Publish `.deb` packages to Debian/Ubuntu repositories or PPA.
  - Publish `.rpm` packages to Fedora COPR.
  - Publish to GitHub Releases with checksums (SHA256).
  - Optional: Publish to Snap Store for convenience.
