---
name: distro-packaging
description: Generate Linux distribution package specs (deb and rpm) for the pamsignal project. Use this skill whenever the user mentions packaging, .deb, .rpm, dpkg, apt, dnf, yum, creating packages, release packaging, debian directory, spec files, or wants to distribute pamsignal for Debian, Ubuntu, Fedora, CentOS, AlmaLinux, or Rocky Linux. Also trigger when the user asks about install/uninstall scripts, maintainer scripts, or package metadata for this project.
---

# Distro Packaging for pamsignal

Generate correct, lintian/rpmlint-clean package specs for pamsignal — a meson-built C daemon with a single library dependency (libsystemd), a systemd unit, and a config file containing credentials.

## Project Facts

These are the current values from the source tree. Read `meson.build` to confirm version before generating specs.

- **Name**: pamsignal
- **Version**: read from `meson.build` `project()` line (currently `0.0.1`)
- **License**: check for LICENSE file; fall back to project metadata
- **Build system**: Meson + Ninja
- **Build dep**: `libsystemd-dev` (deb) / `systemd-devel` (rpm), plus `meson`, `ninja-build`, `pkg-config`, `gcc`
- **Runtime dep**: `libsystemd` (shared lib), `curl` (for alert dispatch via fork+exec)
- **Binary**: `pamsignal` → installs to `/usr/bin/pamsignal`
- **Systemd unit**: `pamsignal.service` → installs to `/usr/lib/systemd/system/pamsignal.service`
- **Config**: `pamsignal.conf.example` → installs as `/etc/pamsignal/pamsignal.conf`
- **System user**: `pamsignal` (nologin, supplementary group `systemd-journal`)
- **Runtime dirs**: `/run/pamsignal/` (managed by systemd `RuntimeDirectory=`)
- **PID file**: `/run/pamsignal/pamsignal.pid`

## Critical Path Corrections

The source tree's `meson.build` uses default prefix (`/usr/local`) and installs the service file to `/etc/systemd/system/`. Both are wrong for distro packages. The package build must fix these at build time — not just document them:

1. **Prefix**: pass `--prefix=/usr` so binary lands in `/usr/bin/`, not `/usr/local/bin/`
2. **Systemd unit dir**: the service file must end up in `/usr/lib/systemd/system/` (vendor unit path), not `/etc/systemd/system/` (admin override path). Since meson.build hardcodes the path, the package build must relocate it: `mv` the file from the wrong location to the correct one in the staging/install step.
3. **ExecStart path**: the service file contains `ExecStart=/usr/local/bin/pamsignal`. The package build must `sed` this to `/usr/bin/pamsignal` during the install phase — this is a build-time fix, not something to punt to the user.
4. **Config file**: `/etc/pamsignal/pamsignal.conf` — mark as conffile (deb) or `%config(noreplace)` (rpm) so user edits survive upgrades.

## System User Handling

The `pamsignal` user must be created before the daemon starts and should not be removed on uninstall (the user may own log data or runtime state).

- **deb**: create in `postinst` using `adduser --system --group --no-create-home --shell /usr/sbin/nologin pamsignal`, then `adduser pamsignal systemd-journal`
- **rpm**: create in `%pre` using `useradd -r -s /sbin/nologin -M pamsignal`, then `usermod -aG systemd-journal pamsignal`
- Both: guard with `id pamsignal` or `getent passwd pamsignal` check so re-installs are idempotent.

## Generating Packages

When the user asks to generate packaging, determine which format(s) they need and read the appropriate reference doc:

- **deb** (Debian, Ubuntu): read `references/deb.md` for the full `debian/` directory structure
- **rpm** (Fedora, CentOS, AlmaLinux, Rocky Linux): read `references/rpm.md` for the `.spec` file

### Workflow

1. Read `meson.build` to confirm current version and source list
2. Check for a LICENSE file to set the license field
3. Generate the package spec files per the reference doc
4. Flag the two meson.build issues that need fixing for proper packaging:
   - Service file install path should use `systemd.pc` to find the unit dir
   - ExecStart path in `pamsignal.service` should be configurable or use `/usr/bin/`
5. Provide build instructions for the target format

### meson.build Patches for Packaging

When generating package specs, also suggest these meson.build improvements that make packaging cleaner:

```meson
# Use systemd's pkg-config to find the correct unit directory
systemd_dep = dependency('systemd', required: false)
if systemd_dep.found()
  systemd_unitdir = systemd_dep.get_variable('systemdsystemunitdir')
else
  systemd_unitdir = '/usr/lib/systemd/system'
endif

install_data('pamsignal.service',
  install_dir: systemd_unitdir
)
```

And in `pamsignal.service`, change ExecStart to use the install prefix:
```
ExecStart=/usr/bin/pamsignal --foreground
```

## Config File Permissions

The config file contains alert credentials (Telegram tokens, webhook URLs). The package must set ownership `root:pamsignal` and mode `0640` on `/etc/pamsignal/pamsignal.conf`. This happens in maintainer scripts (postinst for deb, %post for rpm) since the build system cannot set ownership to a user that doesn't exist at build time.

## What NOT to Include

- No GPG signing setup — that's environment-specific
- No repository upload instructions — varies per org
- No AppImage/Flatpak/Snap — this project targets servers with systemd
- No cross-compilation — native builds only
