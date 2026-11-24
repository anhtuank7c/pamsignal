#!/usr/bin/env bash
# who-did-what — a read-only report of who logged in, who became root, what
# they ran and which watched files they changed, built from the systemd
# journal and the Linux audit log.
#
# Part of the PAMSignal examples. It only reads logs; it never changes the
# system. See README.md next to this file, and docs/ssh-hardening.md Part 2
# for the logging it reads (sudo log, auditd rules).
#
# Usage: sudo ./who-did-what.sh [options] [logins|sudo|commands|files|all]...

set -euo pipefail
export LC_ALL=C

readonly VERSION="1.0.0"
readonly PROG="who-did-what"

USER_FILTER=""
SINCE="today"
UNTIL="now"
RAW=0
SECTIONS=()

usage() {
    cat <<EOF
$PROG $VERSION — who logged in, who became root, what they ran, what they changed.

Usage: sudo $0 [options] [section...]

Sections (default: all):
  logins     successful SSH logins, with the key that was used
  sudo       sudo and su: who became which user, and the commands run with sudo
  commands   every program a person started, even inside a root shell (needs auditd)
  files      changes to files watched by auditd (needs auditd file watches)
  all        all of the above

Options:
  -u, --user NAME    only show what this person did (their login account)
  -s, --since TIME   start of the window (default: today). Anything GNU date
                     understands: "today", "yesterday", "2 hours ago",
                     "2026-11-24 09:00"
  -U, --until TIME   end of the window (default: now)
      --raw          in 'commands', keep the records every login generates
                     (message of the day, systemd user session)
  -h, --help         show this help
  -V, --version      show the version

Reads the journal and /var/log/audit, so run it with sudo. It never changes
anything on the system.
EOF
}

die() {
    printf '%s: %s\n' "$PROG" "$*" >&2
    exit 2
}

note() { printf '  (%s)\n' "$*"; }

# Log lines carry text other people chose (usernames, command arguments).
# Replace control characters so nothing in them can drive the terminal.
sanitize() { sed 's/[[:cntrl:]]/?/g'; }

heading() { printf '\n== %s ==\n' "$*"; }

# journalctl and ausearch exit non-zero when nothing matches; an empty
# window is a normal answer here, not an error.
journal() { journalctl "${JOURNAL_ARGS[@]}" "$@" 2>/dev/null || true; }
audit_search() { ausearch "${AUDIT_ARGS[@]}" "$@" -i 2>/dev/null || true; }

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
        -u | --user)
            [ $# -ge 2 ] || die "$1 needs a value"
            USER_FILTER="$2"
            shift 2
            ;;
        -s | --since)
            [ $# -ge 2 ] || die "$1 needs a value"
            SINCE="$2"
            shift 2
            ;;
        -U | --until)
            [ $# -ge 2 ] || die "$1 needs a value"
            UNTIL="$2"
            shift 2
            ;;
        --raw)
            RAW=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        -V | --version)
            printf '%s %s\n' "$PROG" "$VERSION"
            exit 0
            ;;
        logins | sudo | commands | files | all)
            SECTIONS+=("$1")
            shift
            ;;
        *) die "unknown argument: $1 (see --help)" ;;
        esac
    done
    [ ${#SECTIONS[@]} -gt 0 ] || SECTIONS=(all)
}

want() {
    local s
    for s in "${SECTIONS[@]}"; do
        [ "$s" = all ] || [ "$s" = "$1" ] && return 0
    done
    return 1
}

# --- Time window ------------------------------------------------------------
# journalctl and ausearch take different time syntaxes, so both are derived
# from one epoch value.

resolve_window() {
    SINCE_EPOCH=$(date -d "$SINCE" +%s 2>/dev/null) || die "cannot understand --since '$SINCE'"
    UNTIL_EPOCH=$(date -d "$UNTIL" +%s 2>/dev/null) || die "cannot understand --until '$UNTIL'"
    [ "$SINCE_EPOCH" -le "$UNTIL_EPOCH" ] || die "--since is after --until"
    JOURNAL_ARGS=(--since "@$SINCE_EPOCH" --until "@$UNTIL_EPOCH" -o short-iso --no-pager -q)
    # ausearch takes the date and the time as two separate arguments, and
    # with LC_ALL=C reads the date as MM/DD/YY. --input-logs makes it read the
    # audit log even when stdin is not a terminal (cron, ssh host cmd).
    AUDIT_ARGS=(--input-logs
        --start "$(date -d "@$SINCE_EPOCH" +%m/%d/%y)" "$(date -d "@$SINCE_EPOCH" +%H:%M:%S)"
        --end "$(date -d "@$UNTIL_EPOCH" +%m/%d/%y)" "$(date -d "@$UNTIL_EPOCH" +%H:%M:%S)")
}

# --- logins -------------------------------------------------------------------

# Fingerprint -> "owner: comment" for every key in the usual authorized_keys
# files, so a login line can name the key that was used.
build_key_map() {
    local f owner
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        # Cloud images often leave an empty authorized_keys for root, and
        # ssh-keygen fails on a file with no valid key; neither may stop the report.
        if [ ! -r "$f" ] || [ ! -s "$f" ]; then continue; fi
        owner=$(stat -c %U "$f" 2>/dev/null || echo '?')
        { ssh-keygen -lf "$f" 2>/dev/null || true; } | awk -v owner="$owner" '{
            c = ""
            for (i = 3; i < NF; i++) c = c (c == "" ? "" : " ") $i
            printf "%s\t%s: %s\n", $2, owner, (c == "" ? "(no comment)" : c)
        }'
    done
}

section_logins() {
    heading "Logins (SSH)"
    local keymap
    keymap=$(mktemp)
    build_key_map >"$keymap"
    journal -t sshd -t sshd-session |
        awk -v want="$USER_FILTER" -v keymap="$keymap" '
            BEGIN {
                while ((getline line < keymap) > 0) {
                    split(line, kv, "\t"); key[kv[1]] = kv[2]
                }
                printf "  %-25s %-12s %-22s %-10s %s\n", "TIME", "USER", "FROM", "METHOD", "KEY"
            }
            {
                for (i = 1; i <= NF; i++) if ($i == "Accepted") break
                if (i > NF || $(i + 2) != "for" || $(i + 4) != "from") next
                user = $(i + 3)
                if (want != "" && user != want) next
                fp = $NF
                k = (fp ~ /^SHA256:/) ? (fp in key ? key[fp] : fp " (not in any authorized_keys)") : "-"
                ip = $(i + 5); if (index(ip, ":")) ip = "[" ip "]"   # IPv6: [addr]:port
                printf "  %-25s %-12s %-22s %-10s %s\n", $1, user, ip ":" $(i + 7), $(i + 1), k
                n++
            }
            END { if (!n) print "  (no successful SSH logins in this window)" }' | sanitize
    rm -f "$keymap"
}

# --- sudo / su ----------------------------------------------------------------

section_sudo() {
    heading "Became another user (sudo, su)"
    journal -t sudo -t su |
        awk -v want="$USER_FILTER" '
            BEGIN { printf "  %-25s %-12s %-8s %-6s %s\n", "TIME", "WHO", "AS", "TSID", "COMMAND / EVENT" }
            {
                p = index($0, "]: "); if (!p) next
                msg = substr($0, p + 3); prog = $3; sub(/\[.*/, "", prog)
                # su sessions, from pam_unix: "... for user root(uid=0) by alice(uid=1000)"
                if (msg ~ /^pam_unix\(su(-l)?:session\): session opened for user /) {
                    t = msg; sub(/.* for user /, "", t); sub(/\(.*/, "", t)
                    w = msg; if (!sub(/.* by /, "", w)) w = ""; sub(/\(.*/, "", w)
                    if (w == "") w = "?"
                    if (want != "" && w != want) next
                    printf "  %-25s %-12s %-8s %-6s %s\n", $1, w, t, "-", "su session opened"; n++; next
                }
                if (prog != "sudo" || msg ~ /^pam_/) next
                # sudo: "alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; TSID=000002 ; COMMAND=..."
                sub(/^ +/, "", msg)
                c = index(msg, " : "); if (!c) next
                who = substr(msg, 1, c - 1); rest = substr(msg, c + 3)
                if (want != "" && who != want) next
                as = "?"; tsid = "-"; cmd = ""; ev = ""
                if ((q = index(rest, "COMMAND=")) > 0) { cmd = substr(rest, q + 8); rest = substr(rest, 1, q - 1) }
                np = split(rest, f, / ; /)
                for (j = 1; j <= np; j++) {
                    if (f[j] ~ /^USER=/) as = substr(f[j], 6)
                    else if (f[j] ~ /^TSID=/) tsid = substr(f[j], 6)
                    else if (f[j] !~ /^(TTY|PWD|ENV|GROUP)=/ && f[j] != "") ev = ev (ev == "" ? "" : "; ") f[j]
                }
                sub(/ ;$/, "", ev)
                out = (ev != "" ? "[" ev "] " : "") cmd
                printf "  %-25s %-12s %-8s %-6s %s\n", $1, who, as, tsid, out; n++
            }
            END { if (!n) print "  (no sudo or su activity in this window)" }' | sanitize
}

# --- auditd helpers -------------------------------------------------------------

audit_ready() {
    if ! command -v ausearch >/dev/null 2>&1 || ! command -v auditctl >/dev/null 2>&1; then
        note "auditd is not installed — see docs/ssh-hardening.md, section 2.3"
        return 1
    fi
    if ! AUDIT_RULES=$(auditctl -l 2>/dev/null); then
        note "cannot read the audit rules — run with sudo"
        return 1
    fi
}

audit_user_args() {
    AUDIT_USER_ARGS=()
    if [ -n "$USER_FILTER" ]; then
        local uid
        # A deleted account still has history in the journal sections, but
        # the audit log is searched by numeric ID, which needs the account.
        if ! uid=$(id -u "$USER_FILTER" 2>/dev/null); then
            note "no local account '$USER_FILTER', so its audit records cannot be looked up by login ID"
            return 1
        fi
        AUDIT_USER_ARGS=(-ul "$uid")
    fi
}

# Turns `ausearch -i` events into one line per event. Each event is a group
# of records between "----" lines; fields are split on spaces, and an
# EXECVE argument that itself contains spaces is glued back together.
# shellcheck disable=SC2016  # awk program text: $i is awk's, not the shell's
readonly AUDIT_AWK_COMMON='
    function iso(d, t,   p) { split(d, p, "/"); return "20" p[3] "-" p[1] "-" p[2] "T" substr(t, 1, 8) }
    function field(name,   i) {
        for (i = 1; i <= NF; i++) if (index($i, name "=") == 1) return substr($i, length(name) + 2)
        return ""
    }
    /^type=SYSCALL / {
        when = iso(substr($2, 11), $3)
        auid = field("auid"); uid = field("uid"); pid = field("pid"); ppid = field("ppid")
        ses = field("ses"); tty = field("tty"); comm = field("comm"); exe = field("exe")
        sc = field("syscall"); ok = field("success"); key = field("key"); have = 1
    }
    /^type=EXECVE / {
        argv = ""; cur = ""; started = 0
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^a[0-9]+=/) { if (started) argv = argv (argv == "" ? "" : " ") cur; cur = substr($i, index($i, "=") + 1); started = 1 }
            else if (started) cur = cur " " $i
        }
        if (started) argv = argv (argv == "" ? "" : " ") cur
    }
    /^type=PATH / {
        nt = field("nametype"); nm = field("name")
        if (nt == "PARENT") { if (parent == "") parent = nm } else if (path == "") { path = nm; ptype = nt }
    }
'

# --- commands -------------------------------------------------------------------

section_commands() {
    heading "Commands (auditd, by login ID)"
    audit_ready || return 0
    if ! grep -q 'key=user-cmd' <<<"$AUDIT_RULES"; then
        note "no audit rule with key 'user-cmd' is loaded — see docs/ssh-hardening.md, section 2.3"
        return 0
    fi
    audit_user_args || return 0
    audit_search -k user-cmd "${AUDIT_USER_ARGS[@]}" |
        awk -v raw="$RAW" "$AUDIT_AWK_COMMON"'
            BEGIN { printf "  %-19s %-10s %-8s %-5s %-6s %s\n", "TIME", "WHO", "AS", "SES", "TTY", "COMMAND" }
            # Records every login produces on its own: the message of the day,
            # the systemd user session, and the login shell start-up checks.
            function background(a) {
                return a ~ /update-motd/ || a ~ /^\/usr\/lib\/systemd\/systemd --user/ ||
                       a ~ /^\/usr\/lib\/systemd\/(systemd-executor|user-environment-generators|user-generators)/ ||
                       a ~ /^\/usr\/bin\/locale-check / || a == "locale" || a == "mesg n" ||
                       a ~ /^systemctl --user (set|unset)-environment /
            }
            # Within a login session, anything run as root before the person'"'"'s
            # own first program (their shell or command) was started by the
            # login itself (PAM, message of the day): the person could not
            # have run it yet. Subshells fork without an execve record, so
            # following parent PIDs alone would miss some of it.
            function flush() {
                if (have && argv != "") {
                    if (uid == auid) shell_started[ses] = 1
                    if (!raw && (ppid in quiet || background(argv) || (uid == "root" && !(ses in shell_started)))) quiet[pid] = 1
                    else {
                        printf "  %-19s %-10s %-8s %-5s %-6s %s%s\n", when, auid, uid, ses, tty, argv, (ok == "no" ? "   (failed)" : "")
                        n++
                    }
                }
                have = 0; argv = ""; path = ""; parent = ""
            }
            /^----/ { flush() }
            END {
                flush()
                if (!n) print "  (no commands recorded in this window)"
                else if (!raw) print "  (records generated by every login are hidden; --raw shows them)"
            }' | sanitize
}

# --- files ----------------------------------------------------------------------

section_files() {
    heading "Changes to watched files (auditd)"
    audit_ready || return 0
    local keys
    keys=$(awk '$1 == "-w" { for (i = 1; i < NF; i++) if ($i == "-k") print $(i + 1) }' <<<"$AUDIT_RULES" | sort -u)
    if [ -z "$keys" ]; then
        note "no audit file watches (-w ... -k ...) are loaded — see docs/ssh-hardening.md, section 2.4"
        return 0
    fi
    audit_user_args || return 0
    local k rows
    rows=$(for k in $keys; do
        audit_search -k "$k" "${AUDIT_USER_ARGS[@]}" |
            awk "$AUDIT_AWK_COMMON"'
                function action(s) {
                    if (s ~ /unlink/) return "delete"
                    if (s ~ /rename/) return "rename"
                    if (s ~ /chmod/) return "chmod"
                    if (s ~ /chown/) return "chown"
                    if (s ~ /xattr/) return "xattr"
                    if (s ~ /truncate/) return "truncate"
                    if (s ~ /^(open|openat|openat2|creat)$/) return "write"
                    return s
                }
                function flush(   p) {
                    if (have && key != "" && key != "(null)") {
                        p = (path != "") ? path : parent " (missing file)"
                        printf "  %-19s %-10s %-8s %-8s %-14s %-12s %s%s\n", when, auid, uid, action(sc), key, comm, p, (ok == "no" ? "   (failed)" : "")
                    }
                    have = 0; argv = ""; path = ""; parent = ""; key = ""
                }
                /^----/ { flush() }
                END { flush() }'
    done | sanitize | sort)
    printf '  %-19s %-10s %-8s %-8s %-14s %-12s %s\n' TIME WHO AS ACTION KEY VIA PATH
    if [ -n "$rows" ]; then
        printf '%s\n' "$rows"
    else
        echo "  (no changes to watched files in this window)"
    fi
}

main() {
    parse_args "$@"
    resolve_window
    if [ "$(id -u)" -ne 0 ]; then
        printf '%s: not running as root — other users'"'"' journal entries and the audit log will be missing. Use sudo.\n' "$PROG" >&2
    fi
    printf '%s on %s — %s to %s%s\n' "$PROG" "$(hostname)" \
        "$(date -d "@$SINCE_EPOCH" '+%Y-%m-%d %H:%M')" "$(date -d "@$UNTIL_EPOCH" '+%Y-%m-%d %H:%M')" \
        "${USER_FILTER:+, user $USER_FILTER}" | sanitize
    want logins && section_logins
    want sudo && section_sudo
    want commands && section_commands
    want files && section_files
    return 0
}

main "$@"
