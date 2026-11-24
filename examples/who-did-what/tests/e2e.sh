#!/usr/bin/env bash
# End-to-end test for who-did-what.sh on a real Debian/Ubuntu machine.
#
# DESTRUCTIVE: installs openssh-server and auditd, creates users, loads audit
# rules and changes the sudo configuration.
# Run it only on a throwaway VM or a CI runner, as root:
#     sudo bash examples/who-did-what/tests/e2e.sh
#
# auditd needs a real kernel: containers (and WSL2) cannot load audit rules.

set -uo pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "$0")" && pwd)
WDW="$HERE/../who-did-what.sh"
PW='E2e-Test-Pass-1'
SSHO=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes)
FAILS=0

ok() { printf 'PASS: %s\n' "$*"; }
bad() {
    printf 'FAIL: %s\n' "$*"
    FAILS=$((FAILS + 1))
}
expect() { # expect <description> <pattern> <file>
    if grep -qE -- "$2" "$3"; then ok "$1"; else bad "$1 (no line matching: $2)"; fi
}
expect_not() {
    if grep -qE -- "$2" "$3"; then bad "$1 (unexpected line matching: $2)"; else ok "$1"; fi
}

[ "$(id -u)" -eq 0 ] || {
    echo "run as root" >&2
    exit 2
}

echo "== setup"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq openssh-server sudo auditd >/dev/null
systemctl start ssh auditd
START=$(date '+%Y-%m-%d %H:%M:%S')
sleep 1

for u in alice bob; do
    id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
    echo "$u:$PW" | chpasswd
    rm -f "/tmp/${u}_key" "/tmp/${u}_key.pub"
    ssh-keygen -q -t ed25519 -N '' -C "$u@laptop" -f "/tmp/${u}_key"
    install -d -m 700 -o "$u" -g "$u" "/home/$u/.ssh"
    install -m 600 -o "$u" -g "$u" "/tmp/${u}_key.pub" "/home/$u/.ssh/authorized_keys"
done
usermod -aG sudo alice

# The logging from docs/ssh-hardening.md Part 2, as written there.
printf '%s\n' 'Defaults use_pty' 'Defaults log_output' 'Defaults!/usr/bin/sudoreplay !log_output' >/etc/sudoers.d/10-session-log
chmod 440 /etc/sudoers.d/10-session-log
visudo -cqf /etc/sudoers.d/10-session-log || bad "sudoers file invalid"
mkdir -p /etc/nginx /var/www
echo 'worker_processes 1;' >/etc/nginx/nginx.conf
touch /var/www/old.html
cat >/etc/audit/rules.d/50-user-commands.rules <<'EOF'
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k user-cmd
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=unset -k user-cmd
EOF
cat >/etc/audit/rules.d/60-watch-files.rules <<'EOF'
-w /etc/nginx/ -p wa -k nginx-config
-w /var/www/ -p wa -k webroot
EOF
augenrules --load >/dev/null
auditctl -l | grep -q user-cmd || bad "audit rules did not load"

echo "== activity"
as() { ssh "${SSHO[@]}" -i "/tmp/$1_key" "$1@localhost" "$2" >/dev/null 2>&1; }
as alice "echo '$PW' | sudo -S systemctl is-active ssh"
as alice "printf '%s\n' '$PW' 'systemctl is-active cron' 'echo \"# edited\" >> /etc/nginx/nginx.conf' 'rm -f /var/www/old.html' 'exit' | sudo -S -i"
# A command whose argument carries a real ESC byte (a "clear screen" sequence):
# it must reach the report only as '?'.
ESC=$'\033'
as alice "echo '$PW' | sudo -S printf 'x${ESC}[2Jhidden\n'"
as bob "echo '$PW' | sudo -S id"
sleep 3

OUT=$(mktemp)
echo "== report (all users)"
bash "$WDW" --since "$START" >"$OUT" 2>&1
cat "$OUT"

expect "logins: alice with her key comment" '^  [^ ]+ +alice +(127\.0\.0\.1|\[::1\]):[0-9]+ +publickey +alice: alice@laptop' "$OUT"
expect "logins: bob" '^  [^ ]+ +bob +(127\.0\.0\.1|\[::1\])' "$OUT"
expect "sudo: alice ran systemctl as root" 'alice +root +[0-9A-Z]+ +/usr/bin/systemctl is-active ssh' "$OUT"
expect "sudo: bob refused" 'bob +root .*NOT in sudoers' "$OUT"
expect "commands: command typed inside sudo -i, attributed to alice as root" 'alice +root .*systemctl is-active cron' "$OUT"
expect "commands: rm inside sudo -i" 'alice +root .*rm -f /var/www/old.html' "$OUT"
expect_not "commands: login background (motd) hidden by default" 'run-parts --lsbsysinit|/proc/uptime|sort -r' "$OUT"
expect "files: nginx.conf write by alice as root" 'alice +root +write +nginx-config +bash +/etc/nginx/nginx.conf' "$OUT"
expect "files: delete in /var/www by alice" 'alice +root +delete +webroot +rm +/var/www/old.html' "$OUT"
if grep -q $'\033' "$OUT"; then bad "output contains a raw ESC byte"; else ok "no terminal escape bytes reach the output"; fi

echo "== report (--user bob)"
bash "$WDW" --since "$START" --user bob >"$OUT" 2>&1
cat "$OUT"
expect "filter: bob's login" ' bob +(127\.0\.0\.1|\[::1\])' "$OUT"
expect_not "filter: no alice lines" ' alice ' "$OUT"

echo "== report (--raw commands)"
bash "$WDW" --since "$START" --raw commands >"$OUT" 2>&1
expect "raw: login background shown" 'run-parts|update-motd|systemd --user' "$OUT"

echo "== edge cases"
bash "$WDW" --since "1 minute ago" --until "1 minute ago" >"$OUT" 2>&1
expect "empty window is not an error" 'no successful SSH logins in this window' "$OUT"
if bash "$WDW" --since "not a date" >"$OUT" 2>&1; then
    bad "bad --since accepted"
else
    expect "bad --since rejected" 'cannot understand --since' "$OUT"
fi
bash "$WDW" --user nosuchuser commands >"$OUT" 2>&1
expect "unknown user is a note, not a crash" "no local account 'nosuchuser'" "$OUT"

rm -f "$OUT"
echo
echo "TOTAL FAILS: $FAILS"
[ "$FAILS" -eq 0 ]
