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
journal() { journalctl "${JOURNAL_ARGS[@]}" -o short-iso "$@" 2>/dev/null || true; }
journal_verbose() { journalctl "${JOURNAL_ARGS[@]}" -o verbose "$@" 2>/dev/null || true; }
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
    JOURNAL_ARGS=(--since "@$SINCE_EPOCH" --until "@$UNTIL_EPOCH" --no-pager -q)
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
    # _UID=0: journald sets it from the kernel, so a local user cannot fake
    # it with `logger -t sshd`; sshd logs as root.
    journal -t sshd -t sshd-session _UID=0 |
        awk -v want="$USER_FILTER" -v keymap="$keymap" '
            BEGIN {
                while ((getline line < keymap) > 0) {
                    split(line, kv, "\t"); key[kv[1]] = kv[2]
                }
                printf "  %-25s %-12s %-22s %-10s %s\n", "TIME", "USER", "FROM", "METHOD", "KEY"
            }
            # Anchored, like skip_prefix in src/utils.c: the message must start
            # with "Accepted". A failed attempt embeds the client-chosen
            # username, which may itself read "Accepted password for root ...".
            # Short-iso layout: $1 time, $2 host, $3 "sshd[pid]:", $4 message.
            $3 ~ /^sshd(-session)?\[[0-9]+\]:$/ && $4 == "Accepted" && $6 == "for" && $8 == "from" && $10 == "port" {
                user = $7
                if (want != "" && user != want) next
                fp = $NF
                k = (fp ~ /^SHA256:/) ? (fp in key ? key[fp] : fp " (not in any authorized_keys)") : "-"
                ip = $9; if (index(ip, ":")) ip = "[" ip "]"   # IPv6: [addr]:port
                printf "  %-25s %-12s %-22s %-10s %s\n", $1, user, ip ":" $11, $5, k
                n++
            }
            END { if (!n) print "  (no successful SSH logins in this window)" }' | sanitize
    rm -f "$keymap"
}

# --- sudo / su ----------------------------------------------------------------

section_sudo() {
    heading "Became another user (sudo, su)"
    # Trust comes from _EXE, which journald fills in from /proc/<pid>/exe, so
    # `logger -t sudo` cannot fake it (sudo logs with the caller's UID, so
    # _UID=0 would not work here). journald reads it after the message
    # arrives, though: a sudo that is refused logs and exits at once, and its
    # entry may have no _EXE at all. Such entries are shown and marked
    # UNVERIFIED instead of being dropped; entries whose _EXE is some other
    # program (logger) are dropped.
    local exe sudo_exe="" su_exe=""
    if exe=$(command -v sudo 2>/dev/null); then sudo_exe=$(readlink -f "$exe"); fi
    if exe=$(command -v su 2>/dev/null); then su_exe=$(readlink -f "$exe"); fi
    if [ -z "$sudo_exe" ] && [ -z "$su_exe" ]; then
        note "neither sudo nor su is installed"
        return 0
    fi
    # -o verbose prints one field per line and shows any value with
    # unprintable bytes as "[N bytes blob data]", so a field cannot spill
    # into the next one.
    journal_verbose -t sudo -t su |
        awk -v want="$USER_FILTER" -v sudo_exe="$sudo_exe" -v su_exe="$su_exe" '
            BEGIN { printf "  %-25s %-12s %-8s %-6s %s\n", "TIME", "WHO", "AS", "TSID", "COMMAND / EVENT" }
            function row(t, who, as, tsid, text) {
                printf "  %-25s %-12s %-8s %-6s %s%s\n", t, who, as, tsid, mark, text; n++
            }
            function entry(   t, w, who, rest, probe, nu, nc, as, tsid, cmd, ev, q, np, f, j) {
                if (!have) return
                have = 0
                if (exe != "" && exe != sudo_exe && exe != su_exe) return
                mark = (exe == "") ? "[UNVERIFIED: the sender exited before journald could check it] " : ""
                # su sessions, from pam_unix: "... for user root(uid=0) by alice(uid=1000)"
                if (msg ~ /^pam_unix\(su(-l)?:session\): session opened for user /) {
                    t = msg; sub(/.* for user /, "", t); sub(/\(.*/, "", t)
                    w = msg; if (!sub(/.* by /, "", w)) w = ""; sub(/\(.*/, "", w)
                    if (w == "") w = "?"
                    if (want != "" && w != want) return
                    row(when, w, t, "-", "su session opened"); return
                }
                if (ident != "sudo" || msg ~ /^pam_/) return
                # sudo: "alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; TSID=000002 ; COMMAND=..."
                # PWD (a directory name) and the command arguments are chosen
                # by the user and sit on both sides of USER=, so a line with
                # more than one " ; USER=" or " ; COMMAND=" can be read two
                # ways. Such a line is flagged rather than guessed at.
                sub(/^ +/, "", msg)
                q = index(msg, " : "); if (!q) return
                who = substr(msg, 1, q - 1); rest = substr(msg, q + 3)
                if (want != "" && who != want) return
                probe = rest
                nu = gsub(/ ; USER=/, "", probe); nc = gsub(/ ; COMMAND=/, "", probe)
                if (nu > 1 || nc > 1) {
                    row(when, who, "?", "?", "[AMBIGUOUS: a path or argument contains sudo field separators; check by hand] " rest)
                    return
                }
                as = "?"; tsid = "-"; cmd = ""; ev = ""
                if ((q = index(rest, " ; COMMAND=")) > 0) { cmd = substr(rest, q + 11); rest = substr(rest, 1, q - 1) }
                np = split(rest, f, / ; /)
                for (j = 1; j <= np; j++) {
                    if (f[j] ~ /^USER=/) as = substr(f[j], 6)
                    else if (f[j] ~ /^TSID=/) tsid = substr(f[j], 6)
                    else if (f[j] !~ /^(TTY|PWD|ENV|GROUP)=/ && f[j] != "") ev = ev (ev == "" ? "" : "; ") f[j]
                }
                row(when, who, as, tsid, (ev != "" ? "[" ev "] " : "") cmd)
            }
            # Entry header: "Tue 2026-11-24 06:33:06.123456 +0000 [s=...]"
            /^[^ ]/ {
                entry()
                have = 1; exe = ""; ident = ""; msg = ""
                when = $2 "T" substr($3, 1, 8) ($4 ~ /^[+-][0-9]{4}$/ ? substr($4, 1, 3) ":" substr($4, 4) : "")
                next
            }
            /^    [A-Z_]+=/ {
                k = substr($0, 5, index($0, "=") - 5); v = substr($0, index($0, "=") + 1)
                if (k == "_EXE") exe = v
                else if (k == "SYSLOG_IDENTIFIER") ident = v
                else if (k == "MESSAGE") msg = v
            }
            END {
                entry()
                if (!n) print "  (no sudo or su activity in this window)"
            }' | sanitize
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
    # comm= and exe= are chosen by whoever runs the program and, once
    # interpreted, may contain spaces and "name=value" text. Fields before
    # them are taken at their first occurrence and key= (after them) at its
    # last, so injected text cannot replace the real values.
    function field(name,   i) {
        for (i = 1; i <= NF; i++) if (index($i, name "=") == 1) return substr($i, length(name) + 2)
        return ""
    }
    function field_last(name,   i) {
        for (i = NF; i >= 1; i--) if (index($i, name "=") == 1) return substr($i, length(name) + 2)
        return ""
    }
    /^type=SYSCALL / {
        when = iso(substr($2, 11), $3)
        auid = field("auid"); uid = field("uid"); pid = field("pid"); ppid = field("ppid")
        ses = field("ses"); tty = field("tty"); comm = field("comm"); exe = field("exe")
        sc = field("syscall"); ok = field("success"); key = field_last("key"); have = 1
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
    # Sessions whose login falls inside the window: the kernel writes a
    # LOGIN record (with the new ses=) when a login sets the login ID.
    local logins
    logins=$(audit_search -m LOGIN | awk "$AUDIT_AWK_COMMON"'
        /^type=LOGIN / { s = field("ses"); if (s != "" && s != "unset" && s != "4294967295") print s }' | sort -u | tr '\n' ' ')
    audit_search -k user-cmd "${AUDIT_USER_ARGS[@]}" |
        awk -v raw="$RAW" -v logins="$logins" "$AUDIT_AWK_COMMON"'
            BEGIN {
                n_l = split(logins, l, " "); for (i = 1; i <= n_l; i++) login_seen[l[i]] = 1
                printf "  %-19s %-10s %-8s %-5s %-6s %s\n", "TIME", "WHO", "AS", "SES", "TTY", "COMMAND"
            }
            # Records every login produces on its own. Nothing here keys on
            # text the person controls (argv, comm) or on reusable PIDs:
            #  - inside a session that logged in during the window, programs
            #    run as root before the person'"'"'s own first program (their
            #    shell or command) were started by the login itself (PAM, the
            #    message of the day); the person could not have run anything
            #    yet. This also covers subshell children, which have no execve
            #    of their own to follow.
            #  - the systemd user manager and its helpers, recognised by the
            #    real executable path the kernel records (exe=), which argv0
            #    tricks such as "exec -a" cannot change;
            #  - the exact start-up commands of a login shell.
            function background() {
                if (uid == "root" && (ses in login_seen) && !(ses in shell_started)) return 1
                if (exe == "/usr/lib/systemd/systemd" && ppid == "1" && argv ~ / --user( |$)/) return 1
                if (exe == "/usr/lib/systemd/systemd-executor") return 1
                if (exe ~ /^\/usr\/lib\/systemd\/user-(environment-)?generators\//) return 1
                if (exe == "/usr/bin/systemctl" && argv ~ /^[^ ]*systemctl --user (set|unset)-environment /) return 1
                if (exe == "/usr/bin/locale-check" || (exe == "/usr/bin/locale" && argv == "locale") || (exe == "/usr/bin/mesg" && argv == "mesg n")) return 1
                return 0
            }
            function flush() {
                if (have && argv != "") {
                    if (uid == auid) shell_started[ses] = 1
                    if (!raw && background()) hidden++
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
                if (hidden) printf "  (%d records generated by logins themselves are hidden; --raw shows them)\n", hidden
            }' | sanitize
}

# --- files ----------------------------------------------------------------------

section_files() {
    heading "Changes to watched files (auditd)"
    audit_ready || return 0
    local keys
    # Both rule styles watch files: "-w PATH -p wa -k KEY" and the syscall
    # form used by CIS benchmarks, "-a always,exit -F path=PATH (or dir=)
    # -F perm=wa -F key=KEY" (auditctl may print the key as -k or key=).
    keys=$(awk '
        $1 == "-w" || / -F (path|dir)=/ {
            for (i = 1; i < NF; i++) {
                if ($i == "-k") print $(i + 1)
                else if ($i == "-F" && index($(i + 1), "key=") == 1) print substr($(i + 1), 5)
            }
        }' <<<"$AUDIT_RULES" | grep -vx 'user-cmd' | sort -u || true)
    if [ -z "$keys" ]; then
        note "no audit file watches (-w ... or -F path=/dir= with a key) are loaded — see docs/ssh-hardening.md, section 2.4"
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
