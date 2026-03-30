# Debian/Ubuntu Package Reference

## Directory Structure

Generate these files under `debian/` in the project root:

```
debian/
├── changelog          # Required: version history in deb-changelog format
├── compat             # debhelper compat level (not needed if using debhelper-compat in control)
├── control            # Required: package metadata, deps
├── copyright          # Required: license info in DEP-5 format
├── rules              # Required: build script (makefile calling dh)
├── pamsignal.install   # File placement overrides (if needed)
├── pamsignal.postinst  # Post-install: create user, set perms, enable service
├── pamsignal.prerm     # Pre-remove: stop service
├── pamsignal.postrm    # Post-remove: disable service, cleanup
└── source/
    └── format         # "3.0 (native)" or "3.0 (quilt)"
```

## debian/control

```
Source: pamsignal
Section: admin
Priority: optional
Maintainer: Your Name <your.email@example.com>
Build-Depends: debhelper-compat (= 13),
               meson,
               ninja-build,
               pkg-config,
               libsystemd-dev
Standards-Version: 4.6.2
Homepage: https://github.com/anhtuank7c/pamsignal
Rules-Requires-Root: no

Package: pamsignal
Architecture: any
Depends: ${shlibs:Depends},
         ${misc:Depends},
         curl,
         systemd
Pre-Depends: adduser
Description: Real-time PAM login monitor with multi-channel alerts
 PAMSignal monitors PAM authentication events via the systemd journal.
 It detects login attempts, logouts, and brute-force patterns from sshd,
 sudo, su, and login services, sending alerts to Telegram, Slack, Teams,
 WhatsApp, Discord, or custom webhooks.
```

Key decisions:
- `Section: admin` — security/admin monitoring tool
- `Pre-Depends: adduser` — needed in postinst before the daemon can run
- `Rules-Requires-Root: no` — the build itself doesn't need root; fakeroot handles ownership
- `debhelper-compat (= 13)` — current stable compat level, replaces the `compat` file

## debian/rules

```makefile
#!/usr/bin/make -f

export DEB_BUILD_MAINT_OPTIONS = hardening=+all

%:
	dh $@

override_dh_auto_configure:
	meson setup build --prefix=/usr --sysconfdir=/etc --buildtype=release

override_dh_auto_build:
	meson compile -C build

override_dh_auto_install:
	DESTDIR=$(CURDIR)/debian/pamsignal meson install -C build --no-rebuild
	# Fix: relocate systemd unit from admin path to vendor path
	mkdir -p $(CURDIR)/debian/pamsignal/usr/lib/systemd/system
	mv $(CURDIR)/debian/pamsignal/etc/systemd/system/pamsignal.service \
	   $(CURDIR)/debian/pamsignal/usr/lib/systemd/system/pamsignal.service
	rmdir --ignore-fail-on-non-empty $(CURDIR)/debian/pamsignal/etc/systemd/system 2>/dev/null || true
	rmdir --ignore-fail-on-non-empty $(CURDIR)/debian/pamsignal/etc/systemd 2>/dev/null || true
	# Fix: patch ExecStart to use /usr/bin (meson.build hardcodes /usr/local/bin)
	sed -i 's|/usr/local/bin/pamsignal|/usr/bin/pamsignal|g' \
	   $(CURDIR)/debian/pamsignal/usr/lib/systemd/system/pamsignal.service

override_dh_auto_test:
	meson test -C build -v
```

Key points:
- `--prefix=/usr` — binary goes to `/usr/bin/`, not `/usr/local/bin/`
- `DEB_BUILD_MAINT_OPTIONS = hardening=+all` — enables all dpkg-buildflags hardening (stack protector, FORTIFY_SOURCE, RELRO, PIE)
- The `mv` and `sed` in `dh_auto_install` fix the two meson.build issues at build time: wrong service file path and wrong ExecStart binary path

## debian/changelog

Format (generate with `dch` or write manually):

```
pamsignal (0.0.1-1) unstable; urgency=low

  * Initial release.

 -- Your Name <your.email@example.com>  Thu, 01 Jan 2026 00:00:00 +0000
```

- Version format: `upstream_version-debian_revision` (e.g., `0.0.1-1`)
- The date must be in RFC 2822 format
- Use `UNRELEASED` distribution during development, `unstable` for Debian, or the Ubuntu codename for Ubuntu

## debian/copyright (DEP-5)

```
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: pamsignal
Upstream-Contact: https://github.com/anhtuank7c/pamsignal
Source: https://github.com/anhtuank7c/pamsignal

Files: *
Copyright: 2026 pamsignal contributors
License: <check-LICENSE-file>
```

## debian/source/format

```
3.0 (native)
```

Use `3.0 (native)` if versioning the debian dir inside the upstream repo. Use `3.0 (quilt)` if packaging separately from upstream.

## debian/pamsignal.postinst

```bash
#!/bin/sh
set -e

case "$1" in
    configure)
        # Create system user if it doesn't exist
        if ! getent passwd pamsignal >/dev/null 2>&1; then
            adduser --system --group --no-create-home \
                --home /nonexistent \
                --shell /usr/sbin/nologin \
                pamsignal
        fi

        # Add to systemd-journal group for journal access
        if getent group systemd-journal >/dev/null 2>&1; then
            adduser pamsignal systemd-journal || true
        fi

        # Set config file permissions (contains credentials)
        if [ -f /etc/pamsignal/pamsignal.conf ]; then
            chown root:pamsignal /etc/pamsignal/pamsignal.conf
            chmod 0640 /etc/pamsignal/pamsignal.conf
        fi
    ;;
    abort-upgrade|abort-remove|abort-deconfigure)
    ;;
    *)
        echo "postinst called with unknown argument '$1'" >&2
        exit 1
    ;;
esac

#DEBHELPER#

exit 0
```

The `#DEBHELPER#` token is required — debhelper inserts systemd enable/start commands there.

## debian/pamsignal.prerm

```bash
#!/bin/sh
set -e

#DEBHELPER#

exit 0
```

debhelper handles `systemctl stop` via the `#DEBHELPER#` token.

## debian/pamsignal.postrm

```bash
#!/bin/sh
set -e

case "$1" in
    purge)
        # Remove config directory on purge
        rm -rf /etc/pamsignal
        # Do NOT remove the pamsignal user — it may own journal entries
    ;;
    remove|upgrade|failed-upgrade|abort-install|abort-upgrade|disappear)
    ;;
    *)
        echo "postrm called with unknown argument '$1'" >&2
        exit 1
    ;;
esac

#DEBHELPER#

exit 0
```

## Config File Handling

The config file at `/etc/pamsignal/pamsignal.conf` should be registered as a conffile so dpkg preserves user edits during upgrades. Since debhelper 13 with `dh_installsystemd`, files under `/etc/` installed by the build system are automatically treated as conffiles. Verify with `dpkg-deb -c` and `dpkg-deb --info` after building.

## Build Instructions

```bash
# Install build dependencies
sudo apt-get install -y debhelper meson ninja-build pkg-config libsystemd-dev

# Build the package (from project root)
dpkg-buildpackage -us -uc -b

# The .deb lands in the parent directory
ls ../*.deb

# Install locally
sudo dpkg -i ../pamsignal_0.0.1-1_amd64.deb

# Or with dependency resolution
sudo apt install ../pamsignal_0.0.1-1_amd64.deb
```

## Lintian Checks

```bash
lintian ../pamsignal_0.0.1-1_amd64.deb
```

Common issues to watch for:
- `binary-without-manpage` — pamsignal doesn't ship a man page yet; add `debian/pamsignal.manpages` when one exists
- `no-upstream-changelog` — acceptable for initial release
- `systemd-service-file-refers-to-unusual-wantedby-target` — `multi-user.target` is fine

## Distro-Specific Notes

### Debian
- Target `unstable` (sid) for initial upload, or `stable-backports`
- Standards-Version should match current policy (check debian-policy package)

### Ubuntu
- Target the specific release codename (e.g., `noble`, `jammy`)
- PPA uploads use `~ppa1` suffix: `0.0.1-1~ppa1`
- Build with `debuild` or `sbuild` in a clean chroot for PPA
