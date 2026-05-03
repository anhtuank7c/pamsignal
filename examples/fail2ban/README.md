# Fail2ban Integration

PAMSignal tracks brute-force attempts and writes them to the systemd journal as structured events. Since PAMSignal already calculates thresholds and time windows, you can easily plug it into `fail2ban` to automatically ban attacking IPs without needing to maintain complex regex rules.

This example tells `fail2ban` to watch the journal for `BRUTE_FORCE_DETECTED` events emitted by `pamsignal` and immediately ban the offending IP.

## Installation

Assuming you have `fail2ban` installed on your system:

1. Copy the filter configuration:
   ```bash
   sudo cp filter.d/pamsignal.conf /etc/fail2ban/filter.d/
   ```

2. Copy the jail configuration:
   ```bash
   sudo cp jail.d/pamsignal.conf /etc/fail2ban/jail.d/
   ```

3. Restart fail2ban:
   ```bash
   sudo systemctl restart fail2ban
   ```

## How it works

- **Thresholding is done by PAMSignal**: You configure your brute-force threshold in `/etc/pamsignal/pamsignal.conf` (e.g., `fail_threshold=5`, `fail_window_sec=300`).
- **Fail2ban acts on the alert**: We set `maxretry = 1` in the fail2ban jail because PAMSignal only emits the `BRUTE_FORCE_DETECTED` log *after* the threshold is met. As soon as fail2ban sees this single log line, it bans the IP.
- **Systemd Journal Backend**: Fail2ban reads directly from the systemd journal using `backend = systemd` and efficiently filters by `SYSLOG_IDENTIFIER=pamsignal`.

## Testing

You can test the filter against your current journal to see if it matches any past events:

```bash
fail2ban-regex systemd-journal /etc/fail2ban/filter.d/pamsignal.conf
```
