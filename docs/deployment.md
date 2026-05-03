# Deployment

## Install

The recommended path is the published `.deb` or `.rpm` from the project repo (the same one-liners in the [README quick start](../README.md#1-install)). The packages create the `pamsignal` system user, set the config-file permissions to `root:pamsignal 0640`, and arm the systemd unit for you — when you install via `apt` or `dnf` you can skip straight to [Configure](#configure).

If you build from source, you do those steps yourself; see the "Source build" subsection below.

### Debian / Ubuntu (apt)

```bash
curl -fsSL https://anhtuank7c.github.io/pamsignal/key.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/pamsignal.gpg
echo "deb [signed-by=/usr/share/keyrings/pamsignal.gpg] https://anhtuank7c.github.io/pamsignal stable main" \
  | sudo tee /etc/apt/sources.list.d/pamsignal.list
sudo apt update && sudo apt install pamsignal
```

The package installs `/usr/sbin/pamsignal`, `/usr/lib/systemd/system/pamsignal.service`, `/etc/pamsignal/pamsignal.conf`, and `/usr/share/man/man8/pamsignal.8.gz`. The `pamsignal` user and `systemd-journal` group membership are created in `postinst`. Continue at [Configure](#configure).

### Fedora / RHEL / AlmaLinux / Rocky (dnf)

```bash
# Fedora / CentOS
sudo dnf config-manager addrepo \
  --from-repofile=https://anhtuank7c.github.io/pamsignal/rpm/fedora/pamsignal.repo

# RHEL 9 / AlmaLinux 9 / Rocky Linux 9
sudo dnf config-manager --add-repo \
  https://anhtuank7c.github.io/pamsignal/rpm/el9/pamsignal.repo

sudo dnf install pamsignal
```

Same layout as the deb (`/usr/sbin`, `/usr/lib/systemd/system`, `/etc/pamsignal`, `/usr/share/man/man8/pamsignal.8.gz`). The `pamsignal` user and group are created by the spec's `%pre` block. Continue at [Configure](#configure).

### Source build (`meson install`)

```bash
# Build
meson setup build
meson compile -C build

# Install binary, service file, example config, and man page
sudo meson install -C build
```

With the default `--prefix=/usr/local` you get:

- `/usr/local/sbin/pamsignal` — the binary (FHS §4.10: system administration daemons live in `sbin`)
- `/usr/local/lib/systemd/system/pamsignal.service` — the systemd unit (vendor unit search path)
- `/usr/local/etc/pamsignal/pamsignal.conf` — the example config (from `pamsignal.conf.example`)
- `/usr/local/share/man/man8/pamsignal.8` — the man page

For a system-wide install that mirrors the packaged layout (`/usr/sbin`, `/usr/lib/systemd/system`, `/etc/pamsignal`), reconfigure with `meson setup build --prefix=/usr --sysconfdir=/etc`.

A source build does **not** create the `pamsignal` system user or lock down the config-file permissions — do those steps yourself before starting the service:

```bash
sudo useradd -r -s /usr/sbin/nologin pamsignal
sudo usermod -aG systemd-journal pamsignal

# Locks down the example config so its credentials are readable by the
# daemon (group=pamsignal) but not world-readable. The deb/rpm postinst
# scripts do this for you on packaged installs.
sudo chown root:pamsignal /usr/local/etc/pamsignal/pamsignal.conf
sudo chmod 0640 /usr/local/etc/pamsignal/pamsignal.conf
```

## Configure

Edit the config file. The path depends on how you installed:

- Packaged install (deb/rpm) or source build with `--prefix=/usr --sysconfdir=/etc`: `/etc/pamsignal/pamsignal.conf`
- Source build with default `--prefix=/usr/local`: `/usr/local/etc/pamsignal/pamsignal.conf`

```bash
sudo editor /etc/pamsignal/pamsignal.conf
```

All values are optional — defaults are sane. To enable alerts, add your channel credentials (e.g. Telegram, Slack):

```ini
telegram_bot_token = <bot_token>
telegram_chat_id = <chat_id>
```

See [Configuration](./configuration.md) for all options.

## Start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pamsignal
```

## Verify

```bash
# Check status
sudo systemctl status pamsignal

# Watch logs
journalctl -u pamsignal -f

# Watch only pamsignal events
journalctl -t pamsignal -f
```

## Reload config

After editing `/etc/pamsignal/pamsignal.conf`:

```bash
sudo systemctl reload pamsignal
```

This sends SIGHUP — no downtime, no restart.

## Stop

```bash
sudo systemctl stop pamsignal
```

## Uninstall

The right command depends on how you installed pamsignal. If you used the published `.deb` or `.rpm` (the path in the project README), the package manager unwinds everything for you. The manual recipe is only for installs done from source via `meson install`.

### Packaged install (Debian / Ubuntu, via `apt`)

`dpkg` distinguishes two stages of removal:

```bash
# Soft remove: stops the service, removes the binary / unit / man page,
# but KEEPS your /etc/pamsignal/pamsignal.conf so a later reinstall
# preserves your alert credentials and tuning.
sudo apt remove pamsignal

# Hard remove: stops the service AND wipes /etc/pamsignal/. Use this
# when you really want pamsignal off the host.
sudo apt purge pamsignal
```

The maintainer scripts shipped with the package (`debian/pamsignal.{prerm,postrm}`) handle `systemctl stop`, `systemctl disable`, and `daemon-reload`. The `pamsignal` system user is **intentionally preserved** across both `remove` and `purge` — if any file on the system was created with that UID (a runtime artifact, an unexpected leftover) and the user were deleted, the file would orphan to a numeric UID the kernel could later reuse for a different user. Drop the user manually only after you have confirmed nothing on the system is owned by it:

```bash
sudo find / -user pamsignal 2>/dev/null
sudo userdel pamsignal     # only if the find above returned nothing
```

### Packaged install (Fedora / RHEL / AlmaLinux / Rocky, via `dnf`)

rpm has a single removal verb:

```bash
sudo dnf remove pamsignal
```

There is no equivalent of `apt purge` — `dnf remove` already deletes everything the package put on disk. One subtlety: if you edited `/etc/pamsignal/pamsignal.conf` since install, `rpm` saves your modified copy as `/etc/pamsignal/pamsignal.conf.rpmsave` rather than deleting it (the `%config(noreplace)` directive in `pamsignal.spec`). Remove the `.rpmsave` file by hand if you no longer need your old configuration.

The spec's `%preun` / `%postun` blocks handle systemd lifecycle. The `pamsignal` user is preserved on uninstall for the same reason explained above.

### Source build (`meson install`)

If you ran `sudo meson install -C build` instead of installing a package, no package-manager database tracks what was placed where — you have to undo it explicitly:

```bash
sudo systemctl stop pamsignal
sudo systemctl disable pamsignal
sudo rm /usr/local/sbin/pamsignal
sudo rm /usr/local/lib/systemd/system/pamsignal.service
sudo rm -f /usr/local/share/man/man8/pamsignal.8
sudo rm -rf /usr/local/etc/pamsignal
# systemd's ConfigurationDirectory=pamsignal directive auto-creates
# /etc/pamsignal/ on first unit start regardless of --prefix; for a
# dev install with --prefix=/usr/local this directory is empty and
# unused but is left behind unless removed explicitly.
sudo rm -rf /etc/pamsignal
sudo userdel pamsignal
sudo systemctl daemon-reload
```

`/run/pamsignal/` does not need manual cleanup — `RuntimeDirectory=pamsignal` removes it automatically when the service stops.

If you reconfigured the build with `--prefix=/usr --sysconfdir=/etc` to mirror the packaged layout, replace `/usr/local/sbin`, `/usr/local/lib/systemd/system`, `/usr/local/share/man/man8`, and `/usr/local/etc/pamsignal` with their `/usr/...` and `/etc/...` counterparts.

## Security hardening

The systemd service file includes these security directives:

| Directive | Effect |
|-----------|--------|
| `User=pamsignal` | Runs as unprivileged user |
| `NoNewPrivileges=yes` | Cannot gain new privileges |
| `ProtectSystem=strict` | Filesystem is read-only |
| `ProtectHome=yes` | Home directories hidden |
| `PrivateTmp=yes` | Private `/tmp` mount |
| `MemoryDenyWriteExecute=yes` | No writable+executable memory (W^X) |
| `ProtectKernelTunables=yes` | `/proc/sys` and `/sys` read-only |
| `ProtectKernelModules=yes` | Cannot load kernel modules |
| `ProtectKernelLogs=yes` | Cannot read kernel log buffer |
| `RestrictNamespaces=yes` | Cannot create namespaces |
| `RestrictSUIDSGID=yes` | Cannot set SUID/SGID bits |
| `PrivateDevices=yes` | No access to physical devices |
| `LockPersonality=yes` | Cannot change execution domain |
| `CapabilityBoundingSet=` | All capabilities dropped |
| `SystemCallFilter=@system-service` | Only system-service syscalls allowed |
| `ConfigurationDirectory=pamsignal` | Creates `/etc/pamsignal/` |
| `RuntimeDirectory=pamsignal` | Creates `/run/pamsignal/` |
