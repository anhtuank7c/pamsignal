# RPM Package Reference (Fedora/CentOS/AlmaLinux/Rocky Linux)

## Spec File

Generate `pamsignal.spec` in the project root (or in `packaging/rpm/`).

```spec
Name:           pamsignal
Version:        0.0.1
Release:        1%{?dist}
Summary:        Real-time PAM login monitor with multi-channel alerts

License:        <check-LICENSE-file>
URL:            https://github.com/anhtuank7c/pamsignal
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  meson >= 0.50
BuildRequires:  ninja-build
BuildRequires:  gcc
BuildRequires:  pkg-config
BuildRequires:  systemd-devel
BuildRequires:  systemd-rpm-macros

Requires:       systemd
Requires:       curl
Requires(pre):  shadow-utils

%description
PAMSignal monitors PAM authentication events via the systemd journal.
It detects login attempts, logouts, and brute-force patterns from sshd,
sudo, su, and login services, sending alerts to Telegram, Slack, Teams,
WhatsApp, Discord, or custom webhooks.

%prep
%autosetup -n %{name}-%{version}

%build
%meson
%meson_build

%check
%meson_test

%install
%meson_install

# Fix: relocate systemd unit from admin path to vendor path
# (current meson.build hardcodes /etc/systemd/system/)
mkdir -p %{buildroot}%{_unitdir}
if [ -f %{buildroot}/etc/systemd/system/pamsignal.service ]; then
    mv %{buildroot}/etc/systemd/system/pamsignal.service %{buildroot}%{_unitdir}/pamsignal.service
    rmdir --ignore-fail-on-non-empty %{buildroot}/etc/systemd/system/ 2>/dev/null || true
    rmdir --ignore-fail-on-non-empty %{buildroot}/etc/systemd/ 2>/dev/null || true
fi

# Fix: patch ExecStart to use %{_bindir} (meson.build hardcodes /usr/local/bin)
sed -i 's|/usr/local/bin/pamsignal|%{_bindir}/pamsignal|g' %{buildroot}%{_unitdir}/pamsignal.service

%pre
# Create system user before install
getent passwd pamsignal >/dev/null 2>&1 || \
    useradd -r -s /sbin/nologin -M -d / pamsignal
# Add to systemd-journal group
getent group systemd-journal >/dev/null 2>&1 && \
    usermod -aG systemd-journal pamsignal || true

%post
%systemd_post pamsignal.service
# Set config permissions (contains credentials)
if [ -f %{_sysconfdir}/pamsignal/pamsignal.conf ]; then
    chown root:pamsignal %{_sysconfdir}/pamsignal/pamsignal.conf
    chmod 0640 %{_sysconfdir}/pamsignal/pamsignal.conf
fi

%preun
%systemd_preun pamsignal.service

%postun
%systemd_postun_with_restart pamsignal.service
# Do NOT remove pamsignal user — it may own journal entries

%files
%license LICENSE
%doc README.md
%{_bindir}/pamsignal
%{_unitdir}/pamsignal.service
%dir %attr(0750,root,pamsignal) %{_sysconfdir}/pamsignal
%config(noreplace) %attr(0640,root,pamsignal) %{_sysconfdir}/pamsignal/pamsignal.conf

%changelog
* <date> Your Name <your.email@example.com> - 0.0.1-1
- Initial package
```

Use `%{_sysconfdir}` instead of hardcoded `/etc/pamsignal` — it's the standard RPM way and respects distro overrides.

The `%changelog` section is required by rpmlint and expected by Fedora/EPEL review. Use `date +"%a %b %d %Y"` format for the date (e.g., `Mon Mar 30 2026`).

## Key Decisions

### RPM Macros

The spec uses Fedora/RHEL RPM macros for meson (`%meson`, `%meson_build`, `%meson_install`, `%meson_test`). These automatically pass `--prefix=/usr` and other distro-standard flags. The `systemd-rpm-macros` package provides `%systemd_post`, `%systemd_preun`, `%systemd_postun_with_restart`, and the `%{_unitdir}` macro.

### %config(noreplace)

The config file is marked `%config(noreplace)` so rpm preserves user modifications during upgrades. If the packaged version changes AND the user modified the file, rpm saves the new version as `.rpmnew` and keeps the user's version in place.

### %attr Directives

- Config dir: `0750 root:pamsignal` — only root and the daemon can access
- Config file: `0640 root:pamsignal` — contains credentials, no world-read
- These are also set in `%post` for first-install scenarios where the user is created in `%pre`

### shadow-utils Dependency

`Requires(pre): shadow-utils` ensures `useradd` is available during the `%pre` scriptlet. This is the standard approach for creating system users in RPM packages.

### Service File Relocation

The `%install` section includes a workaround to move the service file from `/etc/systemd/system/` (where meson currently installs it) to `%{_unitdir}` (typically `/usr/lib/systemd/system/`). This is a temporary measure until `meson.build` is updated to use the systemd pkg-config variable for the unit directory.

## Source Tarball

RPM builds expect a source tarball. Generate it from git:

```bash
git archive --format=tar.gz --prefix=pamsignal-0.0.1/ -o pamsignal-0.0.1.tar.gz HEAD
```

## Build Instructions

### Fedora

```bash
# Install build dependencies
sudo dnf install -y meson ninja-build gcc pkg-config systemd-devel rpm-build rpmdevtools

# Set up rpmbuild tree
rpmdev-setuptree

# Copy source tarball
cp pamsignal-0.0.1.tar.gz ~/rpmbuild/SOURCES/

# Build
rpmbuild -ba pamsignal.spec

# Install
sudo dnf install ~/rpmbuild/RPMS/x86_64/pamsignal-0.0.1-1.fc*.x86_64.rpm
```

### CentOS/AlmaLinux/Rocky Linux

```bash
# Install EPEL if needed (for meson)
sudo dnf install -y epel-release

# Install build dependencies
sudo dnf install -y meson ninja-build gcc pkg-config systemd-devel rpm-build rpmdevtools

# Same build steps as Fedora
rpmdev-setuptree
cp pamsignal-0.0.1.tar.gz ~/rpmbuild/SOURCES/
rpmbuild -ba pamsignal.spec
sudo dnf install ~/rpmbuild/RPMS/x86_64/pamsignal-0.0.1-1.el*.x86_64.rpm
```

### Mock (clean chroot builds)

For reproducible builds, use mock:

```bash
# Build SRPM first
rpmbuild -bs pamsignal.spec

# Build in clean chroot for specific distro
mock -r fedora-40-x86_64 ~/rpmbuild/SRPMS/pamsignal-0.0.1-1.fc40.src.rpm
mock -r rocky-9-x86_64 ~/rpmbuild/SRPMS/pamsignal-0.0.1-1.el9.src.rpm
mock -r alma-9-x86_64 ~/rpmbuild/SRPMS/pamsignal-0.0.1-1.el9.src.rpm
```

## rpmlint Checks

```bash
rpmlint pamsignal.spec
rpmlint ~/rpmbuild/RPMS/x86_64/pamsignal-*.rpm
```

Common issues:
- `no-manual-page-for-binary` — no man page yet; add when available
- `spelling-error` — verify any flagged terms are intentional

## Distro-Specific Notes

### Fedora
- `%{?dist}` expands to `.fc40`, `.fc41`, etc.
- Meson macros are in `meson-rpm-macros` (auto-pulled by `meson` package)
- Fedora review guidelines: package must pass `fedora-review` tool

### CentOS Stream / RHEL
- `%{?dist}` expands to `.el9`, `.el10`, etc.
- EPEL may be needed for meson on older releases
- CentOS Stream 9+ has meson in base repos

### AlmaLinux / Rocky Linux
- Binary-compatible with RHEL — same `%{?dist}` tags
- Same EPEL requirement as CentOS for meson
- Build with mock using `alma-9-x86_64` or `rocky-9-x86_64` configs
