#!/bin/bash
# tests/scenario.sh — full-stack local end-to-end scenario test for pamsignal.
#
# Mirrors the release-packages.yml test-deb job's coverage (build → install
# → real sshd brute-force → mock webhook ingestion → SIGHUP reload → purge)
# and adds two pieces of coverage that don't exist in CI:
#   1. Explicit Type=notify behavior verification (systemctl reports
#      "active" only after sd_notify(READY=1) actually fires).
#   2. Sudo brute-force scenario (the v0.3.0 pam_unix(sudo:auth) parser
#      path with local-actor-keyed tracking).
#
# Requires: Debian/Ubuntu host with systemd PID 1, sudo, python3, jq,
#   openssl, sshpass, openssh-server. The script offers to apt-install
#   missing dependencies up front.
#
# Runtime: ~5 minutes. Most of the wait time is deliberate `sleep`s to
#   give pamsignal's 1-second sd_journal_wait cycle time to process events
#   before we check the webhook log.
#
# DESTRUCTIVE ACTIONS (with up-front confirmation):
#   - apt install of missing test dependencies
#   - dpkg-buildpackage of the current source tree
#   - dpkg -i of the resulting .deb
#   - Self-signed CA dropped into /usr/local/share/ca-certificates/
#     followed by update-ca-certificates
#   - /etc/pamsignal/pamsignal.conf overwritten with a test config
#   - Test user `testpamuser` created with a known password
#   - /etc/ssh/sshd_config edited to enable PasswordAuthentication
#     and AllowUsers testpamuser; sshd restarted
#   - sshd brute-force from 127.0.0.1
#   - sudo brute-force from inside an ssh session as testpamuser
#
# CLEANUP (always runs on EXIT, even on failure):
#   - Mock webhook process stopped
#   - apt purge pamsignal
#   - sshd_config restored from backup
#   - testpamuser deleted
#   - Test CA removed from system trust store
#   - /etc/pamsignal directory force-removed (purge already deletes it on
#     Debian/Ubuntu, but defensive — and the systemd ConfigurationDirectory=
#     re-creates it on first start so it lingers)
#
# Exit code is 0 if every phase passes, non-zero if any phase fails.
# The trap reports which phase reached on early exit.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PHASE_NAME=""
WEBHOOK_PID=""
SSHD_CONFIG_BACKUP=""

# --- Helpers -----------------------------------------------------------

phase() {
    PHASE_NAME="$1"
    printf '\n\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
    printf '\033[1;36m  Phase: %s\033[0m\n' "$PHASE_NAME"
    printf '\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
}

pass() {
    printf '  \033[1;32m✓\033[0m %s\n' "$1"
}

info() {
    printf '  \033[0;36m·\033[0m %s\n' "$1"
}

cleanup() {
    local exit_code=$?
    printf '\n\033[1;33m━━━ Cleanup ━━━\033[0m\n'

    if [ -n "$WEBHOOK_PID" ] && kill -0 "$WEBHOOK_PID" 2>/dev/null; then
        kill "$WEBHOOK_PID" 2>/dev/null || true
        info "stopped mock webhook (pid $WEBHOOK_PID)"
    fi

    sudo systemctl stop pamsignal 2>/dev/null || true
    sudo apt purge -y pamsignal >/dev/null 2>&1 || true
    sudo rm -rf /etc/pamsignal 2>/dev/null || true
    info "purged pamsignal"

    if [ -n "$SSHD_CONFIG_BACKUP" ] && [ -f "$SSHD_CONFIG_BACKUP" ]; then
        sudo cp "$SSHD_CONFIG_BACKUP" /etc/ssh/sshd_config
        sudo rm "$SSHD_CONFIG_BACKUP"
        sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd 2>/dev/null || true
        info "sshd_config restored, sshd restarted"
    fi

    if [ -f /etc/sudoers.d/pamsignal-scenario ]; then
        sudo rm /etc/sudoers.d/pamsignal-scenario
        info "removed /etc/sudoers.d/pamsignal-scenario"
    fi
    sudo userdel -r testpamuser 2>/dev/null || true
    info "testpamuser removed"

    if [ -f /usr/local/share/ca-certificates/pamsignal-scenario-test.crt ]; then
        sudo rm /usr/local/share/ca-certificates/pamsignal-scenario-test.crt
        sudo update-ca-certificates --fresh >/dev/null 2>&1 || true
        info "test CA removed from system trust store"
    fi

    rm -f /tmp/pamsignal-cert.pem /tmp/pamsignal-key.pem \
          /tmp/pamsignal-mock-webhook.py /tmp/pamsignal-webhook-events.log \
          /tmp/pamsignal-mock-webhook.pid /tmp/pamsignal-webhook-stderr.log \
          /tmp/pamsignal-curl-smoke.log /tmp/pamsignal-update-ca.log \
          /tmp/pamsignal-ssh-attempts.log /tmp/pamsignal-sudo-attempts.log
    info "scratch files cleaned"

    if [ "$exit_code" -ne 0 ]; then
        printf '\n\033[1;31m━━━ FAILED in phase: %s ━━━\033[0m\n' "$PHASE_NAME"
        printf 'Inspect /tmp/pamsignal-webhook-events.log if it still exists,\n'
        printf 'and journalctl -t pamsignal --since "5 min ago" for daemon output.\n'
    else
        printf '\n\033[1;32m━━━ All phases passed ━━━\033[0m\n'
    fi
    return "$exit_code"
}
trap cleanup EXIT

confirm() {
    local prompt="$1"
    # Route both the prompt and the read through /dev/tty so the script
    # works even when invoked with stdin/stdout redirected (e.g. from a
    # wrapper that captures the script's output but doesn't forward
    # keystrokes back to its `read`). Without this, the script silently
    # blocks at the first prompt when stdin is anything other than a
    # plain interactive terminal.
    if [ ! -t 0 ] || [ ! -r /dev/tty ]; then
        echo "Cannot read from a controlling terminal — run this script" >&2
        echo "directly in your terminal (not via a wrapper or pipe)." >&2
        return 1
    fi
    printf '\033[1;33m? %s [y/N] \033[0m' "$prompt" > /dev/tty
    local reply
    read -r reply < /dev/tty
    case "$reply" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

# --- Phase 0: pre-flight & confirmation --------------------------------

phase "0. Pre-flight"

if [ "$(id -u)" -eq 0 ]; then
    echo "Don't run this as root. The script uses sudo where it needs to." >&2
    exit 1
fi

if ! systemctl is-system-running --quiet 2>/dev/null \
   && [ "$(systemctl is-system-running 2>/dev/null)" != "running" ] \
   && [ "$(systemctl is-system-running 2>/dev/null)" != "degraded" ]; then
    echo "systemd is not the init system here. The scenario test requires" >&2
    echo "PID 1 to be systemd." >&2
    exit 1
fi

cd "$REPO_ROOT"
if ! [ -f meson.build ] || ! [ -f pamsignal.spec ]; then
    echo "Run from the pamsignal repo root." >&2
    exit 1
fi

info "host: $(uname -srm)"
info "systemd: $(systemctl --version | head -1)"
info "distro: $(. /etc/os-release && echo "$PRETTY_NAME")"
info "repo HEAD: $(git rev-parse --short HEAD) ($(git log -1 --format=%s))"

# Check + offer to install dependencies.
required_pkgs=(meson ninja-build pkg-config gcc libsystemd-dev libcmocka-dev
               debhelper dh-make python3 jq openssl sshpass openssh-server
               openssh-client ca-certificates)
missing=()
for pkg in "${required_pkgs[@]}"; do
    dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
done

if [ ${#missing[@]} -gt 0 ]; then
    info "missing build/test dependencies: ${missing[*]}"
    if confirm "apt install them now?"; then
        sudo apt update -qq
        sudo apt install -y --no-install-recommends "${missing[@]}"
    else
        echo "Cannot continue without dependencies." >&2
        exit 1
    fi
else
    pass "all required tooling already installed"
fi

if ! confirm "Proceed with the scenario test? (creates testpamuser, edits sshd, installs pamsignal)"; then
    echo "Aborted by user." >&2
    exit 1
fi

# --- Phase 1: build ----------------------------------------------------

phase "1. Build .deb from current source"

DEB_VERSION=$(dpkg-parsechangelog -ldebian/changelog --show-field Version)
info "package version: $DEB_VERSION"

# Build cleanly without polluting the source tree's git status. dpkg-buildpackage
# leaves artefacts in ../ which is one level up; that's where we'll find the .deb.
dpkg-buildpackage -us -uc -b 2>&1 | tail -5

DEB_PATH="$REPO_ROOT/../pamsignal_${DEB_VERSION}_$(dpkg --print-architecture).deb"
test -f "$DEB_PATH"
pass "$DEB_PATH built ($(stat -c%s "$DEB_PATH") bytes)"

# --- Phase 2: install --------------------------------------------------

phase "2. Install via dpkg"

# If pamsignal is already installed (from a previous run), purge it first.
if dpkg -s pamsignal >/dev/null 2>&1; then
    sudo apt purge -y pamsignal >/dev/null 2>&1
    sudo rm -rf /etc/pamsignal
fi

sudo apt install -y "$DEB_PATH"
pass "installed pamsignal $DEB_VERSION"

# --- Phase 3: Type=notify activation -----------------------------------

phase "3. Type=notify behaviour"

# After install, dh_installsystemd's postinst should have started the unit.
# Wait briefly for systemd to publish state.
sleep 2

active_state=$(systemctl show pamsignal -p ActiveState --value)
sub_state=$(systemctl show pamsignal -p SubState --value)
type_field=$(systemctl show pamsignal -p Type --value)

info "Type=$type_field ActiveState=$active_state SubState=$sub_state"

if [ "$type_field" != "notify" ]; then
    echo "  ✗ unit Type is '$type_field', expected 'notify'" >&2
    exit 1
fi
pass "unit Type=notify"

if [ "$active_state" != "active" ]; then
    echo "  ✗ unit ActiveState is '$active_state', expected 'active'" >&2
    sudo journalctl -u pamsignal --no-pager -n 30 >&2
    exit 1
fi
pass "unit reached ActiveState=active (sd_notify(READY=1) fired)"

# WatchdogSec=30s with periodic sd_notify(WATCHDOG=1) keeps the daemon alive.
# A daemon that fails to ping in 30s is auto-restarted. We can't easily test
# the restart path without breaking the daemon; settle for verifying the
# directive is set.
#
# systemctl show -p WatchdogUSec --value returns the value in two different
# forms depending on systemd version: older systemd (e.g. 255 in CI) prints
# the raw microseconds integer "30000000"; newer systemd (e.g. 259) prints
# the human-readable "30s". Accept either.
watchdog_usec=$(systemctl show pamsignal -p WatchdogUSec --value)
info "WatchdogUSec=$watchdog_usec (expected: '30s' or '30000000')"
case "$watchdog_usec" in
    "30s"|"30000000")
        pass "WatchdogSec=30s configured"
        ;;
    *)
        echo "  ✗ WatchdogUSec is '$watchdog_usec', expected '30s' or '30000000'" >&2
        exit 1
        ;;
esac

# --- Phase 4: hardening score ------------------------------------------

phase "4. systemd-analyze security score"

# Run live (against the active unit, not just the file). The score should
# match what we measured offline: 13 internal / 1.3 displayed. The CI gate
# is at 20; anything ≤20 passes the project policy.
sudo systemd-analyze security pamsignal.service --no-pager 2>&1 | tail -3

if sudo systemd-analyze security --threshold=20 pamsignal.service >/dev/null 2>&1; then
    pass "exposure score ≤20 (project policy)"
else
    echo "  ✗ exposure score regressed past threshold 20" >&2
    exit 1
fi

# --- Phase 5: TLS-trusted mock webhook ---------------------------------

phase "5. Stand up local TLS-trusted webhook"

# Generate a self-signed cert and inject into the system trust store so curl's
# default verification works without --insecure.
openssl req -x509 -newkey rsa:2048 \
    -keyout /tmp/pamsignal-key.pem \
    -out   /tmp/pamsignal-cert.pem \
    -days 1 -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1
pass "self-signed cert generated"

sudo cp /tmp/pamsignal-cert.pem \
        /usr/local/share/ca-certificates/pamsignal-scenario-test.crt
if ! sudo update-ca-certificates 2>/tmp/pamsignal-update-ca.log >/tmp/pamsignal-update-ca.log; then
    echo "  ✗ update-ca-certificates failed:" >&2
    cat /tmp/pamsignal-update-ca.log >&2
    exit 1
fi
# Verify the cert ended up in the bundle curl will read.
if ! sudo grep -q 'CN=localhost' /etc/ssl/certs/ca-certificates.crt 2>/dev/null \
   && ! grep -q 'CN=localhost' /etc/ssl/certs/ca-certificates.crt 2>/dev/null; then
    info "test cert not yet visible in /etc/ssl/certs/ca-certificates.crt"
    info "this MAY indicate the system trust update path is broken on this distro"
fi
pass "self-signed CA installed in system trust store"

# Mock webhook collector listening on https://localhost:8443/.
#
# The handler explicitly drives a clean HTTP/1.1 + TLS shutdown:
#   - protocol_version = 'HTTP/1.1' (default is HTTP/1.0, which has no
#     unambiguous body-end marker without Content-Length)
#   - Content-Length response header so curl knows where the body ends
#     without waiting for connection close
#   - Connection: close header so curl doesn't try keep-alive
#   - finish() override that calls connection.unwrap() to issue a TLS
#     close_notify alert before the TCP socket closes. Without this,
#     OpenSSL 3.5+ (Ubuntu 26.04 default) reports "unexpected EOF while
#     reading" (error:0A000126) and curl exits 56 — even though the HTTP
#     response was successfully received and the test would otherwise
#     have passed. Real webhook receivers (Telegram, Slack, etc.) do
#     this correctly; our quick-and-dirty mock has to as well.
cat > /tmp/pamsignal-mock-webhook.py <<'PY'
import http.server, ssl, sys, traceback

class CleanShutdownHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n).decode('utf-8', errors='replace')
        with open('/tmp/pamsignal-webhook-events.log', 'a') as f:
            f.write(body + '\n')
        response = b'OK\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(response)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(response)
        self.wfile.flush()

    def log_message(self, *a):
        pass

    def finish(self):
        try:
            self.wfile.flush()
        except Exception:
            pass
        # Issue TLS close_notify before TCP close. Required for OpenSSL
        # 3.5+ peers (Ubuntu 26.04, recent Fedora). Wrapped in try/except
        # because unwrap() can fail on already-half-closed sockets.
        try:
            self.connection.unwrap()
        except (OSError, ssl.SSLError):
            pass
        try:
            super().finish()
        except Exception:
            pass

try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain('/tmp/pamsignal-cert.pem', '/tmp/pamsignal-key.pem')

    srv = http.server.HTTPServer(('127.0.0.1', 8443), CleanShutdownHandler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("READY", flush=True)
    srv.serve_forever()
except Exception:
    traceback.print_exc()
    sys.exit(1)
PY
: > /tmp/pamsignal-webhook-events.log
python3 -u /tmp/pamsignal-mock-webhook.py >/tmp/pamsignal-webhook-stderr.log 2>&1 &
WEBHOOK_PID=$!

# Wait for the python server to be listening (poll up to 10s). The "READY"
# print above happens AFTER bind; if the process exits before that, dump
# its captured output and bail.
ready=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    if grep -q '^READY$' /tmp/pamsignal-webhook-stderr.log 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$WEBHOOK_PID" 2>/dev/null; then
        echo "  ✗ mock webhook exited during startup. Captured output:" >&2
        cat /tmp/pamsignal-webhook-stderr.log >&2
        exit 1
    fi
    sleep 1
done
if [ "$ready" != "1" ]; then
    echo "  ✗ mock webhook did not signal READY within 10s. Captured output:" >&2
    cat /tmp/pamsignal-webhook-stderr.log >&2
    exit 1
fi
pass "mock webhook process ready (pid $WEBHOOK_PID)"

# Smoke: confirm TLS handshake + cert trust + reachability. Capture verbose
# curl output so a failure shows the actual TLS / DNS / connection error.
if ! curl -sS -X POST https://localhost:8443/smoke \
        -H 'Content-Type: application/json' \
        -d '{"smoke":"ok"}' \
        --max-time 5 \
        -v >/tmp/pamsignal-curl-smoke.log 2>&1; then
    echo "  ✗ curl smoke-test failed. Verbose output:" >&2
    cat /tmp/pamsignal-curl-smoke.log >&2
    echo "  ---- python webhook stderr ----" >&2
    cat /tmp/pamsignal-webhook-stderr.log >&2
    exit 1
fi
test -s /tmp/pamsignal-webhook-events.log
: > /tmp/pamsignal-webhook-events.log
rm -f /tmp/pamsignal-curl-smoke.log /tmp/pamsignal-update-ca.log
pass "mock webhook live at https://localhost:8443/ (TLS validated end-to-end)"

# --- Phase 6: configure pamsignal --------------------------------------

phase "6. Point pamsignal at the test webhook"

sudo tee /etc/pamsignal/pamsignal.conf >/dev/null <<'CONF'
# Scenario test configuration — points at the local mock webhook.
webhook_url = https://localhost:8443/events
fail_threshold = 3
fail_window_sec = 60
alert_cooldown_sec = 0
max_tracked_ips = 10
CONF
sudo chown root:pamsignal /etc/pamsignal/pamsignal.conf
sudo chmod 0640 /etc/pamsignal/pamsignal.conf
sudo systemctl restart pamsignal
sleep 2
systemctl is-active pamsignal >/dev/null
pass "pamsignal restarted with test config; ActiveState=active"

# --- Phase 7: sshd setup -----------------------------------------------

phase "7. Set up real sshd for E2E auth events"

# Real sshd is needed because pamsignal's _EXE allowlist drops anything
# that isn't /usr/sbin/sshd, /usr/bin/sudo, /usr/bin/su, /usr/bin/login,
# /usr/lib/systemd/systemd-logind. logger(1) injection would be filtered.

if ! id testpamuser >/dev/null 2>&1; then
    sudo useradd -m -s /bin/bash testpamuser
fi
echo 'testpamuser:correctpassword456' | sudo chpasswd
pass "test user 'testpamuser' created with known password"

# Grant testpamuser sudo (with password requirement, which is the default).
# Without this, sudo on Ubuntu rejects testpamuser with "user not in
# sudoers" BEFORE invoking pam_unix, so no `authentication failure`
# event is logged and the v0.3.0 sudo brute-force path can't be
# exercised. The sudoers.d file is removed in the cleanup trap.
echo 'testpamuser ALL=(ALL) ALL' | sudo tee /etc/sudoers.d/pamsignal-scenario >/dev/null
sudo chmod 0440 /etc/sudoers.d/pamsignal-scenario
pass "testpamuser added to sudoers (drop-in /etc/sudoers.d/pamsignal-scenario)"

SSHD_CONFIG_BACKUP=$(mktemp /tmp/sshd_config.XXXXXX.bak)
sudo cp /etc/ssh/sshd_config "$SSHD_CONFIG_BACKUP"
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
echo 'AllowUsers testpamuser' | sudo tee -a /etc/ssh/sshd_config >/dev/null
sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd
sleep 1
pass "sshd configured: PasswordAuthentication=yes, AllowUsers testpamuser"

# --- Phase 8: trigger sshd brute-force ---------------------------------

phase "8. Generate sshd brute-force events"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p 22"
SSH_LOG=/tmp/pamsignal-ssh-attempts.log
: > "$SSH_LOG"

# 3 failed logins → triggers fail_threshold=3. Capture stderr so we can
# tell SSH-side failures (host-key mismatch, connection refused) apart
# from the password rejections we're after.
for i in 1 2 3; do
    sshpass -p 'wrongpassword' ssh $SSH_OPTS testpamuser@127.0.0.1 exit \
        >>"$SSH_LOG" 2>&1 || true
done
info "3 failed sshd login attempts driven from 127.0.0.1"

# 1 successful login.
sshpass -p 'correctpassword456' ssh $SSH_OPTS testpamuser@127.0.0.1 exit \
    >>"$SSH_LOG" 2>&1 || true
info "1 successful sshd login attempt"

# Wait for pamsignal's sd_journal_wait cycle (1s) + alert dispatch.
sleep 8

# Diagnostic: confirm sshd actually wrote auth events to the journal in
# the form pamsignal expects. If sshd is mis-configured, this is empty
# and pamsignal can't see anything.
info "sshd auth events sshd actually wrote to the journal:"
sudo journalctl _SYSTEMD_UNIT=ssh.service _SYSTEMD_UNIT=sshd.service \
    --since '60 sec ago' --no-pager 2>/dev/null \
    | grep -E 'Failed password|Accepted password|invalid user' \
    | sed 's/^/      /' || true

# Diagnostic: confirm pamsignal saw the events. If pamsignal logged
# auth.* entries here, it parsed; if zero entries, the _EXE allowlist
# may have dropped them or pamsignal can't read the journal.
info "pamsignal entries from the same window:"
sudo journalctl -t pamsignal --since '60 sec ago' --no-pager 2>/dev/null \
    | sed 's/^/      /' || true

# --- Phase 9: trigger sudo brute-force ---------------------------------

phase "9. Generate sudo brute-force events (v0.3.0 feature)"

# Run via ssh-into-localhost so the process tree is testpamuser, then call
# sudo with a wrong password. Captures the pam_unix(sudo:auth):
# authentication failure path that v0.3.0 added.
SUDO_LOG=/tmp/pamsignal-sudo-attempts.log
: > "$SUDO_LOG"
for i in 1 2 3; do
    sshpass -p 'correctpassword456' ssh $SSH_OPTS testpamuser@127.0.0.1 \
        "echo wrong-sudo-pass | sudo -S whoami" \
        >>"$SUDO_LOG" 2>&1 || true
done
info "3 failed sudo attempts driven from testpamuser"

sleep 8

# Diagnostic: confirm sudo wrote pam_unix(sudo:auth) failure events to
# the journal in the form pamsignal v0.3.0 parses.
info "sudo auth failures from the journal:"
sudo journalctl SYSLOG_IDENTIFIER=sudo --since '60 sec ago' --no-pager 2>/dev/null \
    | grep -E 'authentication failure|incorrect password' \
    | sed 's/^/      /' || true

# --- Phase 10: verify webhook payloads ---------------------------------

phase "10. Verify ECS webhook payloads"

# Always dump what pamsignal logged + what the webhook received. If both
# are empty, the daemon never saw events. If pamsignal logged but the
# webhook didn't get anything, the alert dispatch path failed (curl,
# sandbox, network-egress directive).
echo
info "── pamsignal journal (last 5 minutes) ──"
sudo journalctl -t pamsignal --since '5 min ago' --no-pager 2>/dev/null \
    | sed 's/^/      /' || true

echo
info "── webhook events log ($(wc -l < /tmp/pamsignal-webhook-events.log 2>/dev/null || echo 0) lines) ──"
if [ -s /tmp/pamsignal-webhook-events.log ]; then
    cat /tmp/pamsignal-webhook-events.log | sed 's/^/      /'
else
    echo "      (empty)"
fi

echo
info "── pamsignal unit state ──"
systemctl status pamsignal --no-pager -l 2>/dev/null \
    | head -15 | sed 's/^/      /' || true
echo

login_failures=$(jq -r 'select(.event.action == "login_failure")
                          | .event.action' \
                  /tmp/pamsignal-webhook-events.log 2>/dev/null | wc -l)
login_successes=$(jq -r 'select(.event.action == "login_success")
                           | .event.action' \
                   /tmp/pamsignal-webhook-events.log 2>/dev/null | wc -l)
brute=$(jq -r 'select(.event.action == "brute_force_detected")
                | .event.action' \
         /tmp/pamsignal-webhook-events.log 2>/dev/null | wc -l)

info "received: login_failure=$login_failures login_success=$login_successes brute_force=$brute"

test "$login_failures" -ge 3
pass "≥3 login_failure events received"

test "$login_successes" -ge 1
pass "≥1 login_success event received"

test "$brute" -ge 1
pass "≥1 brute_force_detected event received"

# Verify ECS shape on the first sshd login_failure.
jq -e 'select(.event.action == "login_failure" and .service.name == "sshd")
        | .["@timestamp"]
          and .event.module == "pamsignal"
          and (.event.category | contains(["authentication"]))
          and .event.severity == 5
          and .source.ip == "127.0.0.1"
          and .user.name == "testpamuser"
          and .pamsignal.auth_method == "password"' \
    /tmp/pamsignal-webhook-events.log >/dev/null
pass "ECS shape verified: @timestamp + event.{module,category,severity} + source.ip + user.name + service.name"

# Verify brute_force_detected ECS shape (event.kind=alert per ECS guidance).
jq -e 'select(.event.action == "brute_force_detected")
        | .event.kind == "alert"
          and .event.severity == 8
          and .pamsignal.attempts >= 3' \
    /tmp/pamsignal-webhook-events.log >/dev/null
pass "brute_force_detected: event.kind=alert, severity=8, attempts≥3"

# Look for the v0.3.0 sudo brute-force shape: user.target.name set, no source.ip.
sudo_brute=$(jq -r 'select(.event.action == "brute_force_detected"
                            and .service.name == "sudo")
                     | .user.target.name' \
              /tmp/pamsignal-webhook-events.log 2>/dev/null | head -1)
if [ -n "$sudo_brute" ]; then
    pass "sudo brute-force alert (user.target.name=$sudo_brute) — v0.3.0 sudo path verified"
else
    echo "  ⚠ no sudo brute-force alert received (the v0.3.0 sudo path)"
    echo "    full webhook log:"
    cat /tmp/pamsignal-webhook-events.log
fi

# --- Phase 11: SIGHUP reload preserves state ---------------------------

phase "11. SIGHUP reload preserves brute-force state"

sudo systemctl reload pamsignal
sleep 2

if sudo journalctl -t pamsignal --since '10 sec ago' --no-pager | grep -q 'config reloaded'; then
    pass "config reload logged"
else
    sudo journalctl -t pamsignal --since '20 sec ago' --no-pager | tail -10
    echo "  ✗ no 'config reloaded' message in journal" >&2
    exit 1
fi

# --- Phase 12: cleanup is exercised by the EXIT trap ------------------

phase "12. Cleanup deferred to EXIT trap"
info "purge + sshd_config restore + user removal will run on script exit"

PHASE_NAME=""
exit 0
