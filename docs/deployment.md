# Deployment

## Install

```bash
# Build
meson setup build
meson compile -C build

# Install binary, service file, and example config
sudo meson install -C build
```

This installs:
- `/usr/local/bin/pamsignal` — the binary
- `/etc/systemd/system/pamsignal.service` — the systemd service
- `/etc/pamsignal/pamsignal.conf` — the example config (from `pamsignal.conf.example`)

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

```bash
sudo systemctl stop pamsignal
sudo systemctl disable pamsignal
sudo rm /usr/local/bin/pamsignal
sudo rm /etc/systemd/system/pamsignal.service
sudo rm -rf /etc/pamsignal
sudo userdel pamsignal
sudo systemctl daemon-reload
```

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
