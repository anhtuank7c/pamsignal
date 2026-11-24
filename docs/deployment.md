# Deployment

> **English** · [Tiếng Việt](vi/deployment.md)

## Install

The recommended path is the published `.deb` or `.rpm` from the project repo (the same one-liners in the [README quick start](../README.md#1-install)). The packages create the `pamsignal` system user, add it to the `systemd-journal` group, and set the config-file permissions to `root:pamsignal 0640`. The `.deb` also enables and starts the unit; on Fedora / RHEL the unit follows the distribution's preset policy, so run the commands in [Start the service](#start-the-service). When you install via `apt` or `dnf` you can skip straight to [Configure](#configure).

If you build from source, you do those steps yourself; see the "Source build" subsection below.

### Debian / Ubuntu (apt)

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://anhtuank7c.github.io/pamsignal/key.asc \
  | sudo gpg --dearmor -o /etc/apt/keyrings/pamsignal.gpg
echo "deb [signed-by=/etc/apt/keyrings/pamsignal.gpg] https://anhtuank7c.github.io/pamsignal stable main" \
  | sudo tee /etc/apt/sources.list.d/pamsignal.list
# Refresh only the PamSignal repo, so an unrelated broken repo can't block the install
sudo apt update -o Dir::Etc::sourcelist="sources.list.d/pamsignal.list" \
  -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"
sudo apt install pamsignal
```

The scoped `apt update` refreshes only `pamsignal.list`. If an unrelated third-party repo on the box is broken (e.g. an expired `NO_PUBKEY`), a plain `apt update && apt install` would exit non-zero and never reach the install; the `-o Dir::Etc::*` flags sidestep that by reading only PamSignal's source. Drop the flags if you'd rather run a full `apt update`.

`/etc/apt/keyrings` is the standard location for system-administrator-installed APT signing keys (per `sources.list(5)`); the `install -d` line is idempotent and safe to re-run on systems where the directory already exists.

The package installs `/usr/bin/pamsignal`, `/usr/lib/systemd/system/pamsignal.service`, `/etc/pamsignal/pamsignal.conf`, `/usr/share/man/man8/pamsignal.8.gz`, and `/usr/share/man/man5/pamsignal.conf.5.gz`. The `pamsignal` user and `systemd-journal` group membership are created in `postinst`. Continue at [Configure](#configure).

### Ubuntu 20.04 (Focal)

There is no apt repository for Focal. Each release attaches a signed Focal build (`pamsignal_<version>-1_focal_amd64.deb` plus a detached `.asc`) to the [GitHub release](https://github.com/anhtuank7c/pamsignal/releases):

```bash
VERSION=0.7.1
curl -fLO "https://github.com/anhtuank7c/pamsignal/releases/download/v${VERSION}/pamsignal_${VERSION}-1_focal_amd64.deb"
sudo apt install "./pamsignal_${VERSION}-1_focal_amd64.deb"
```

See [Supported distributions](./distros.md) for the Focal caveats.

### Fedora / RHEL / AlmaLinux / Rocky (dnf)

```bash
# Fedora
sudo dnf config-manager addrepo \
  --from-repofile=https://anhtuank7c.github.io/pamsignal/rpm/fedora/pamsignal.repo

# RHEL 9 / AlmaLinux 9 / Rocky Linux 9
sudo dnf config-manager --add-repo \
  https://anhtuank7c.github.io/pamsignal/rpm/el9/pamsignal.repo

sudo dnf install pamsignal
```

Same layout as the deb (`/usr/bin`, `/usr/lib/systemd/system`, `/etc/pamsignal`, the `pamsignal(8)` and `pamsignal.conf(5)` man pages); `/etc/pamsignal` itself is `root:pamsignal 0750`. The `pamsignal` user and group are created by the spec's `%pre` block. Continue at [Configure](#configure).

### Source build (`meson install`)

```bash
# Build
meson setup build
meson compile -C build

# Install binary, service file, example config, and man pages
sudo meson install -C build
```

With the default `--prefix=/usr/local` you get:

- `/usr/local/bin/pamsignal`: the binary (modern systemd-era convention: admin-oriented daemons share `/usr/bin` with everything else, matching `journalctl`, `systemctl`, `podman`, `containerd`)
- `/usr/local/lib/systemd/system/pamsignal.service`: the systemd unit (vendor unit search path)
- `/usr/local/etc/pamsignal/pamsignal.conf`: the example config (from `pamsignal.conf.example`)
- `/usr/local/share/man/man8/pamsignal.8` and `/usr/local/share/man/man5/pamsignal.conf.5`: the man pages

For a system-wide install that mirrors the packaged layout (`/usr/bin`, `/usr/lib/systemd/system`, `/etc/pamsignal`), reconfigure with `meson setup build --prefix=/usr --sysconfdir=/etc`.

A source build does **not** create the `pamsignal` system user or lock down the config-file permissions. Do those steps yourself before starting the service:

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

All values are optional; defaults are sane. To enable alerts, add your channel credentials (e.g. Telegram, Slack):

```ini
telegram_bot_token = <bot_token>
telegram_chat_id = <chat_id>
```

See [Configuration](./configuration.md) for all options.

Check the file and send a test message before you apply it. Both commands refuse to run as root; run them as the service user so the file-ownership checks match what the daemon sees:

```bash
sudo -u pamsignal pamsignal --check-config   # validate, list enabled channels, exit 0 if OK
sudo -u pamsignal pamsignal --test-alert     # send a test message to every configured channel
```

### Custom webhook authentication

If you point `webhook_url` at your own SIEM or receiver, configure authentication with `webhook_auth_header` (Bearer token, API key, etc.) or, for environments that already run a PKI, `webhook_client_cert` + `webhook_client_key` for mTLS:

```bash
# Place client cert + key under the daemon's config directory.
sudo install -d -o root -g pamsignal -m 0750 /etc/pamsignal
sudo install -o root -g pamsignal -m 0644 webhook-client.crt /etc/pamsignal/
sudo install -o pamsignal -g pamsignal -m 0600 webhook-client.key /etc/pamsignal/
```

The daemon rejects the config if `webhook_client_key` is group- or world-readable, so a `0640` key (the layout `pamsignal.conf` itself uses) is refused. The key must be owned by root or by the daemon user; since only the owner may read it, use `pamsignal:pamsignal 0600`. The certificate and CA bundle are not secret and may be `0644`. If your cert manager (cert-manager, certbot, `systemd-creds`) deploys keys elsewhere, point `webhook_client_key` at that path; pamsignal opens it with `O_NOFOLLOW` and validates ownership and mode at every config load. See [Configuration → Custom webhook authentication](./configuration.md#custom-webhook-authentication) for the full reference.

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

This sends SIGHUP: no downtime, no restart. The daemon loads the file into a temporary copy and swaps it in only if it is valid; otherwise it logs `pamsignal: config reload failed, keeping current config` and keeps running with the old settings. A successful reload keeps the brute-force failure counters and cooldowns (the table is only trimmed if `max_tracked_ips` shrinks). Run `--check-config` first to see why a file is rejected.

## Stop

```bash
sudo systemctl stop pamsignal
```

## Upgrade

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install --only-upgrade pamsignal

# Fedora / RHEL / AlmaLinux / Rocky
sudo dnf upgrade pamsignal
```

Both packages restart the running service after the upgrade. Your edited `/etc/pamsignal/pamsignal.conf` is kept: if the packaged default changed too, `dpkg` asks before replacing your modified conffile, and `rpm` (`%config(noreplace)`) keeps yours and writes the new default next to it as `pamsignal.conf.rpmnew`. On Focal, download the new release's `.deb` and run `sudo apt install ./<file>.deb` again. For a source build, rebuild, run `sudo meson install -C build`, then `sudo systemctl daemon-reload && sudo systemctl restart pamsignal`.

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

The debhelper snippets in the package's maintainer scripts stop the unit on removal, run `daemon-reload`, and drop its enablement state on `purge`; on `purge`, `debian/pamsignal.postrm` also deletes `/etc/pamsignal/` including any files you added there. The `pamsignal` system user is **intentionally preserved** across both `remove` and `purge`. If any file on the system was created with that UID (a runtime artifact, an unexpected leftover) and the user were deleted, the file would orphan to a numeric UID the kernel could later reuse for a different user. Drop the user manually only after you have confirmed nothing on the system is owned by it:

```bash
sudo find / -user pamsignal 2>/dev/null
sudo userdel pamsignal     # only if the find above returned nothing
```

### Packaged install (Fedora / RHEL / AlmaLinux / Rocky, via `dnf`)

rpm has a single removal verb:

```bash
sudo dnf remove pamsignal
```

There is no equivalent of `apt purge`: `dnf remove` already deletes everything the package put on disk. One subtlety: if you edited `/etc/pamsignal/pamsignal.conf` since install, `rpm` saves your modified copy as `/etc/pamsignal/pamsignal.conf.rpmsave` rather than deleting it (the `%config(noreplace)` directive in `pamsignal.spec`). Remove the `.rpmsave` file by hand if you no longer need your old configuration.

The spec's `%preun` / `%postun` blocks handle systemd lifecycle. The `pamsignal` user is preserved on uninstall for the same reason explained above.

### Source build (`meson install`)

If you ran `sudo meson install -C build` instead of installing a package, no package-manager database tracks what was placed where, so you have to undo it explicitly:

```bash
sudo systemctl stop pamsignal
sudo systemctl disable pamsignal
sudo rm /usr/local/bin/pamsignal
sudo rm /usr/local/lib/systemd/system/pamsignal.service
sudo rm -f /usr/local/share/man/man8/pamsignal.8
sudo rm -f /usr/local/share/man/man5/pamsignal.conf.5
sudo rm -rf /usr/local/etc/pamsignal
# systemd's ConfigurationDirectory=pamsignal directive auto-creates
# /etc/pamsignal/ on first unit start regardless of --prefix; for a
# dev install with --prefix=/usr/local this directory is empty and
# unused but is left behind unless removed explicitly.
sudo rm -rf /etc/pamsignal
sudo userdel pamsignal
sudo systemctl daemon-reload
```

`/run/pamsignal/` does not need manual cleanup: `RuntimeDirectory=pamsignal` removes it automatically when the service stops.

If you reconfigured the build with `--prefix=/usr --sysconfdir=/etc` to mirror the packaged layout, replace `/usr/local/bin`, `/usr/local/lib/systemd/system`, `/usr/local/share/man/man8`, `/usr/local/share/man/man5`, and `/usr/local/etc/pamsignal` with their `/usr/...` and `/etc/...` counterparts.

## Security hardening

The shipped unit (`pamsignal.service.in`) sets these service and security directives. `systemd-analyze security pamsignal.service` reports the resulting exposure score; the release workflow fails if it rises above 2.0 (internal threshold 20).

| Directive | Effect |
|-----------|--------|
| `Type=notify`, `NotifyAccess=main` | The unit counts as started only after the daemon sends `READY=1`, once the journal watch is set up |
| `WatchdogSec=30s` | The main loop pings the watchdog; if it stalls for 30 seconds, systemd kills and restarts the daemon |
| `ExecStart=/usr/bin/pamsignal --foreground` | Runs in the foreground under systemd (path follows the install prefix) |
| `Restart=on-failure`, `RestartSec=5` | Restarts 5 seconds after a crash |
| `ExecReload=/bin/kill -HUP $MAINPID` | `systemctl reload` sends SIGHUP |
| `User=pamsignal`, `Group=pamsignal` | Runs as an unprivileged user |
| `SupplementaryGroups=systemd-journal` | Read access to the system journal |
| `Environment=PATH=/usr/bin:/bin` | Minimal `PATH` (curl is still executed by absolute path) |
| `RuntimeDirectory=pamsignal` | Creates `/run/pamsignal/` (PID file), removed on stop |
| `ConfigurationDirectory=pamsignal` | Creates `/etc/pamsignal/` |
| `NoNewPrivileges=yes` | Cannot gain new privileges |
| `ProtectSystem=strict` | Filesystem is read-only |
| `ProtectHome=yes` | Home directories hidden |
| `PrivateTmp=yes` | Private `/tmp` mount |
| `ProtectKernelTunables=yes` | `/proc/sys` and `/sys` read-only |
| `ProtectKernelModules=yes` | Cannot load kernel modules |
| `ProtectKernelLogs=yes` | Cannot read kernel log buffer |
| `ProtectControlGroups=yes` | cgroup hierarchy read-only |
| `MemoryDenyWriteExecute=yes` | No writable+executable memory (W^X) |
| `RestrictNamespaces=yes` | Cannot create namespaces |
| `RestrictRealtime=yes` | Cannot use realtime scheduling |
| `RestrictSUIDSGID=yes` | Cannot set SUID/SGID bits |
| `LockPersonality=yes` | Cannot change execution domain |
| `PrivateDevices=yes` | No access to physical devices |
| `DevicePolicy=closed` | Only the standard pseudo-devices (`null`, `zero`, `random`, ...) |
| `CapabilityBoundingSet=` | All capabilities dropped |
| `SystemCallFilter=@system-service` and `~@privileged @resources` | Only system-service syscalls, minus the privileged and resource-control sets |
| `SystemCallArchitectures=native` | Only the native syscall ABI (no 32-bit compat entry points) |
| `ProtectClock=yes` | Cannot change the system clock |
| `ProtectHostname=yes` | Cannot change the hostname |
| `ProtectProc=invisible`, `ProcSubset=pid` | Other users' processes and non-process `/proc` entries hidden |
| `RemoveIPC=yes` | SysV IPC objects of the service user removed on stop |
| `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6` | Only local sockets, netlink, and IPv4/IPv6 (for the curl child) |
| `UMask=0077` | Files the daemon creates are owner-only |
