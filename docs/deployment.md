# Deployment

## Install

```bash
# Build
meson setup build
meson compile -C build

# Install binary, service file, and example config
sudo meson install -C build
```

This installs (with the default `--prefix=/usr/local`):
- `/usr/local/sbin/pamsignal` — the binary (FHS §4.10: system administration daemons live in `sbin`)
- `/usr/local/lib/systemd/system/pamsignal.service` — the systemd unit (vendor unit search path)
- `/usr/local/etc/pamsignal/pamsignal.conf` — the example config (from `pamsignal.conf.example`)

For a system-wide install that mirrors the packaged layout (`/usr/sbin`, `/usr/lib/systemd/system`, `/etc/pamsignal`), reconfigure with `meson setup build --prefix=/usr --sysconfdir=/etc`.

## Create the service user

```bash
sudo useradd -r -s /usr/sbin/nologin pamsignal
sudo usermod -aG systemd-journal pamsignal
```

## Configure

Edit the config file (all values are optional — defaults are sane):

```bash
sudo editor /etc/pamsignal/pamsignal.conf
```

To enable alerts, add your channel credentials (e.g. Telegram, Slack):

```ini
telegram_bot_token = <bot_token>
telegram_chat_id = <chat_id>
```

Since the config may contain credentials, set restricted permissions:

```bash
sudo chown root:pamsignal /etc/pamsignal/pamsignal.conf
sudo chmod 0640 /etc/pamsignal/pamsignal.conf
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
