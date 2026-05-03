Name:           pamsignal
Version:        0.3.1
Release:        1%{?dist}
Summary:        Real-time PAM login monitor with multi-channel alerts

License:        MIT
URL:            https://github.com/anhtuank7c/pamsignal
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  meson >= 0.50
BuildRequires:  ninja-build
BuildRequires:  gcc
BuildRequires:  pkg-config
BuildRequires:  systemd-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  libcmocka-devel

Requires:       systemd
Requires:       curl
Requires(pre):  shadow-utils

# %files declares %attr(...,pamsignal) which makes RPM auto-generate
# Requires: user(pamsignal) and Requires: group(pamsignal). The user and
# group are created by %pre as part of THIS package's install, so we
# Provides them explicitly — otherwise dnf rejects the transaction at
# resolution time, before %pre has a chance to run.
Provides:       user(pamsignal)
Provides:       group(pamsignal)

%description
PAMSignal monitors PAM authentication events via the systemd journal.
It detects login attempts, logouts, and brute-force patterns from sshd,
sudo, su, and login services, sending alerts to Telegram, Slack, Microsoft
Teams, WhatsApp, Discord, or custom webhooks.

The daemon runs as an unprivileged system user with read-only access to
the journal, isolates the alert dispatch path via fork+exec of curl, and
ships with systemd hardening directives (NoNewPrivileges, ProtectSystem,
SystemCallFilter, MemoryDenyWriteExecute, etc.).

%prep
%autosetup -n %{name}-%{version}

%build
%meson
%meson_build

%check
%meson_test

%install
%meson_install

%pre
# Create the pamsignal group and system user before file install. shadow-utils
# provides groupadd/useradd; the Requires(pre) above ensures they're present.
# Group is created explicitly so `Provides: group(pamsignal)` is honored even
# on systems where USERGROUPS_ENAB is unset and useradd would otherwise skip
# auto-creating the matching group.
getent group pamsignal >/dev/null 2>&1 || groupadd -r pamsignal
getent passwd pamsignal >/dev/null 2>&1 || \
    useradd -r -g pamsignal -s /sbin/nologin -M -d /nonexistent \
            -c "PAMSignal daemon" pamsignal

# Grant read access to the journal.
getent group systemd-journal >/dev/null 2>&1 && \
    usermod -aG systemd-journal pamsignal || true
exit 0

%post
%systemd_post pamsignal.service

# The config file holds alert credentials (Telegram tokens, webhook URLs).
# Owner stays root so only admins can edit; group is pamsignal mode 0640 so
# the daemon can read.
if [ -f %{_sysconfdir}/pamsignal/pamsignal.conf ]; then
    chown root:pamsignal %{_sysconfdir}/pamsignal/pamsignal.conf
    chmod 0640 %{_sysconfdir}/pamsignal/pamsignal.conf
fi

%preun
%systemd_preun pamsignal.service

%postun
%systemd_postun_with_restart pamsignal.service
# The pamsignal user is intentionally NOT removed — it may own journal
# entries or runtime state outside our control.

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/pamsignal
%{_unitdir}/pamsignal.service
# Trailing * matches the .gz suffix added by Fedora's brp-compress hook so
# the file list is correct whether or not compression ran.
%{_mandir}/man8/pamsignal.8*
%dir %attr(0750,root,pamsignal) %{_sysconfdir}/pamsignal
%config(noreplace) %attr(0640,root,pamsignal) %{_sysconfdir}/pamsignal/pamsignal.conf

%changelog
* Sun May 03 2026 Tuan Nguyen <anhtuank7c@hotmail.com> - 0.3.1-1
- BREAKING (revert of v0.3.0 path move): daemon binary moves from
  /usr/sbin/pamsignal back to /usr/bin/pamsignal to align with the
  systemd-era convention that admin-oriented commands (journalctl,
  systemctl, podman, containerd) all live in /usr/bin despite being
  administrator tools. Fedora 42+ has formally retired the bin/sbin
  split (sbindir == bindir == /usr/bin); Debian Trixie has the
  merge on its roadmap. v0.3.0's FHS section 4.10 reading is
  historically valid but on the wrong side of where the ecosystem
  is moving. rpm handles the relocation atomically on upgrade and
  the unit's ExecStart is updated in lockstep via meson
  configure_file. Anyone who scripted against the /usr/sbin/pamsignal
  path that v0.3.0 introduced for the ~30 minutes it was on the dnf
  gh-pages repo needs to revert to /usr/bin/pamsignal.

* Sun May 03 2026 Tuan Nguyen <anhtuank7c@hotmail.com> - 0.3.0-1
- NEW: detect failed sudo/su password attempts and emit a brute-force
  alert when the per-actor threshold is crossed. Parser recognizes the
  pam_unix authentication-failure message format; tracker keys by source
  IP when rhost is set (SSH-to-sudo chains) or by ruser otherwise.
  Per-event chat alerts suppressed for sudo/su login failures so a
  single mistyped password does not spam channels.
- BREAKING: daemon binary moves from /usr/bin/pamsignal to
  /usr/sbin/pamsignal (FHS section 4.10). rpm handles the relocation
  atomically on upgrade; the unit's ExecStart is updated in lockstep
  via meson configure_file. Update any scripts referencing the
  absolute /usr/bin/pamsignal path.
- BREAKING: legacy PAMSIGNAL_ underscore journal fields removed. Update
  saved journalctl queries that filter by PAMSIGNAL_EVENT to use
  EVENT_ACTION instead. Full field mapping in CHANGELOG.md.
- Packaging: install section drops the post-install mv (out of
  /etc/systemd/system) and sed (/usr/bin to /usr/sbin) workarounds; the
  meson configure_file emits the unit in the vendor unit dir directly
  with the right ExecStart path. The pre script creates the pamsignal
  group explicitly before useradd so the group provides resolves even
  on hosts with USERGROUPS_ENAB unset.
- Add pamsignal(8) man page; the files list glob tolerates either the
  compressed or uncompressed form.
- Security: close two clang-analyzer taint-source findings (config-file
  isspace and getgroups malloc); both defensive narrowings with no
  exploitable vulnerabilities closed.
- Docs: docs/deployment.md Install and Uninstall sections split by
  install path (apt / dnf / source build).

* Sun May 03 2026 Tuan Nguyen <anhtuank7c@hotmail.com> - 0.2.4-1
- Add optional server context tags (`provider`, `service_name`) to alert
  payloads. When configured in `pamsignal.conf` they are appended to
  chat-text alerts and injected under the ECS `labels.*` dictionary in
  JSON webhook payloads.
- docs: TypeScript Express webhook receiver example and Bruno test
  collection; expand custom-webhook integration docs.
- ci(test-deb): drive the functional test with real sshd auth events
  instead of `logger -t sshd` (the v0.2.3 `_EXE` allowlist drops the
  latter).
- ci: pin `environment: release` on every release job so secrets resolve
  consistently.

* Sat May 02 2026 Tuan Nguyen <anhtuank7c@hotmail.com> - 0.2.3-1
- Security: enforce a `_EXE` allowlist on every journal entry so
  unprivileged users can no longer inject fake PAM events via logger(1)
  to trigger false alerts or brute-force lockouts. Only entries whose
  `_EXE` resolves to sshd / sudo / su / login / systemd-logind under a
  system prefix (/usr/, /bin/, /sbin/, /lib/, /lib64/, /opt/) are
  processed; entries with a missing `_EXE` are dropped.
- Fix: brute-force tracker now zeroes `last_brute_alert_usec` on the
  evict-and-reuse path so a new IP doesn't inherit the evicted IP's
  alert cooldown.
- Fix: `SIGHUP` reload preserves the in-memory brute-force tracking
  table instead of zeroing it. Existing per-IP attempt counts and
  cooldowns survive a config reload.

* Sat May 02 2026 Tuan Nguyen <anhtuank7c@hotmail.com> - 0.2.2-1
- Republish signed apt + dnf repository on the canonical GitHub Pages URL
  (https://anhtuank7c.github.io/pamsignal/) after the custom domain was
  removed from the gh-pages site. No source or packaging logic changes —
  binary is identical to v0.2.1; this release simply triggers the
  publish-repo workflow against the github.io origin so users following
  the install instructions in README.md get a working repo.

* Thu Apr 30 2026 Tuan Nguyen <anhtuank7c@hotmail.com> - 0.2.1-1
- Packaging release: signed apt and dnf repositories published to GitHub
  Pages. Adds Provides: user(pamsignal) / group(pamsignal) so the auto-
  generated user/group Requires from %attr(...,pamsignal) in %files
  resolves cleanly under dnf 5 (Fedora 44).
- No source code changes — binary is identical to v0.2.0.

* Thu Apr 30 2026 Tuan Nguyen <anhtuank7c@hotmail.com> - 0.2.0-1
- Align alert payloads with Elastic Common Schema (ECS). Breaking change to
  chat text and JSON webhook formats; see CHANGELOG.md for migration.
- Chat text: severity-prefixed key=value with a new pid= field for direct
  `kill <pid>` from the alert.
- JSON webhook: nested ECS objects plus pamsignal.* namespace.
- systemd-journal: ECS-aligned fields added alongside legacy PAMSIGNAL_*.

* Wed Apr 29 2026 Tuan Nguyen <anhtuank7c@hotmail.com> - 0.1.0-1
- Initial RPM packaging.
- Six-phase OWASP 2025 / data-integrity / memory-safety audit closed every
  Critical, High, Medium, Low, and Info finding identified.
- Alert dispatch hardened: secrets via memfd-backed curl config (not argv);
  absolute-path execv; --proto =https forced.
- PID file via openat under O_DIRECTORY|O_NOFOLLOW dirfd; stale removal
  only after kill(pid,0) confirms ESRCH.
- Per-source-IP brute-force cooldown.
- Compiler hardening: _FORTIFY_SOURCE=3, stack-clash, CET, separate-code.
- 78 CMocka tests across four suites; opt-in libFuzzer harness for the
  PAM message parser.
