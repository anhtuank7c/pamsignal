// Integration tests: parse -> track -> notify pipeline.
//
// Per-module behaviour is covered elsewhere:
//   - tests/test_utils.c          : ps_parse_message field extraction
//   - tests/test_journal_watch.c  : fail_table tracking with synthetic events
//   - tests/test_notify.c         : format_*_json / format_*_text with
//                                   hand-built inputs
//
// This suite covers the wiring those module tests cannot: that the parser's
// output shape is compatible with the tracker's input shape, and that the
// tracker's stored state plus the breaching event carries enough information
// for the notify layer to emit a payload that matches the original log line.
// The fixtures are real-looking journal strings, not synthetic structs.
//
// We #include BOTH journal_watch.c and notify.c into this translation unit
// so we can drive file-static helpers from each (fail_table, format_brute_json
// etc) without exposing them in the public headers. The meson rule therefore
// must NOT also list src/journal_watch.c or src/notify.c — that would yield
// duplicate symbols. src/utils.c and src/config.c are still linked normally.

#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

// Stubs for signal-handler flags declared extern in init.h. The integration
// suite never calls into the journal main loop, but the linker still needs
// definitions for these symbols referenced through the included sources.
volatile sig_atomic_t running = 0;
volatile sig_atomic_t reload_requested = 0;

// NOLINTNEXTLINE(bugprone-suspicious-include)
#include "../src/journal_watch.c"
// NOLINTNEXTLINE(bugprone-suspicious-include)
#include "../src/notify.c"

// --- Fixtures ---

static int setup(void **state) {
    (void)state;
    ps_config_defaults(&g_config);
    g_config.fail_threshold = 3;
    g_config.fail_window_sec = 300;
    g_config.max_tracked_ips = 16;
    g_config.alert_cooldown_sec = 0;
    int rc = ps_fail_table_init(g_config.max_tracked_ips);
    assert_int_equal(rc, PS_OK);
    return 0;
}

static int teardown(void **state) {
    (void)state;
    free(fail_table);
    fail_table = NULL;
    fail_table_count = 0;
    fail_table_capacity = 0;
    return 0;
}

// Push one raw log line through parse + track, stamping it with a timestamp,
// hostname, and pid the way the journal-reader path would. Returns the
// fully-populated event so the caller can snapshot the breaching event's
// fields for alert-payload assertions.
//
// Precondition: log_line must parse to PS_EVENT_LOGIN_FAILED. The helper
// calls ps_track_failed_login unconditionally, mirroring journal_watch.c's
// behaviour for failure events only; passing a success/session line would
// silently track a non-failure event and skew the fail_table.
static ps_pam_event_t parse_and_track(const char *log_line, uint64_t ts_usec,
                                      const char *hostname, pid_t pid) {
    ps_pam_event_t event;
    assert_int_equal(ps_parse_message(log_line, &event), PS_OK);
    event.timestamp_usec = ts_usec;
    if (hostname)
        snprintf(event.hostname, sizeof(event.hostname), "%s", hostname);
    event.pid = pid;
    ps_track_failed_login(&event);
    return event;
}

// --- Scenario 1: SSH brute force from a single IPv4 source ---
//
// Three "Failed password" lines from the same IP within the window should
// produce a single IP-keyed entry that has been reset (count == 0) and
// armed (last_brute_alert_usec != 0). The alert payload that the notify
// layer would dispatch must carry the parsed IP, the user from the breaching
// line, the journal-supplied hostname, the pid, and the configured window.

static void test_ssh_brute_force_ipv4_end_to_end(void **state) {
    (void)state;

    const char *log_line =
        "Failed password for root from 203.0.113.5 port 22 ssh2";
    const uint64_t base_ts = 1700000000000000ULL;
    ps_pam_event_t breaching = {0};

    for (int i = 0; i < 3; i++) {
        breaching =
            parse_and_track(log_line, base_ts + (uint64_t)i * 1000000ULL,
                            "honeypot01", 9000 + i);
    }

    assert_int_equal(fail_table_count, 1);
    assert_int_equal(fail_table[0].key_type, PS_FAIL_KEY_IP);
    assert_string_equal(fail_table[0].key, "203.0.113.5");
    assert_int_equal(fail_table[0].count, 0);
    assert_int_not_equal(fail_table[0].last_brute_alert_usec, 0);

    // Reproduce the exact call emit_brute_force_alert would make through
    // ps_notify_brute_force -> format_brute_json. If any field were dropped
    // or mis-keyed along the parse -> track path, the resulting JSON would
    // not contain the values we extracted from the original log line.
    char json[2048];
    format_brute_json(&g_config, fail_table[0].key, g_config.fail_threshold,
                      g_config.fail_window_sec, breaching.username,
                      breaching.hostname, breaching.timestamp_usec,
                      breaching.pid, json, sizeof(json));

    assert_non_null(strstr(json, "\"action\":\"brute_force_detected\""));
    assert_non_null(strstr(json, "\"ip\":\"203.0.113.5\""));
    assert_non_null(strstr(json, "\"name\":\"root\""));
    assert_non_null(strstr(json, "\"hostname\":\"honeypot01\""));
    assert_non_null(strstr(json, "\"pid\":9002"));
    assert_non_null(strstr(json, "\"attempts\":3"));
    assert_non_null(strstr(json, "\"window_sec\":300"));
}

// --- Scenario 2: SSH brute force from an IPv6 source ---
//
// Confirms the parser's IPv6 capture survives the round-trip into the
// tracker's key buffer (which must accept INET6_ADDRSTRLEN-sized strings)
// and back out into the alert JSON.

static void test_ssh_brute_force_ipv6_end_to_end(void **state) {
    (void)state;

    const char *log_line =
        "Failed password for admin from 2001:db8::1 port 443 ssh2";
    const uint64_t base_ts = 1700000000000000ULL;
    ps_pam_event_t breaching = {0};

    for (int i = 0; i < 3; i++) {
        breaching = parse_and_track(
            log_line, base_ts + (uint64_t)i * 1000000ULL, "edge01", 5000);
    }

    assert_int_equal(fail_table[0].key_type, PS_FAIL_KEY_IP);
    assert_string_equal(fail_table[0].key, "2001:db8::1");

    char json[2048];
    format_brute_json(&g_config, fail_table[0].key, g_config.fail_threshold,
                      g_config.fail_window_sec, breaching.username,
                      breaching.hostname, breaching.timestamp_usec,
                      breaching.pid, json, sizeof(json));

    assert_non_null(strstr(json, "\"ip\":\"2001:db8::1\""));
    assert_non_null(strstr(json, "\"name\":\"admin\""));
}

// --- Scenario 3: Pure-local sudo brute force ---
//
// pam_unix(sudo:auth) lines with an empty rhost must produce a local-user
// keyed entry. The alert payload uses the local-brute formatter, which puts
// the actor at user.name and the elevation target at user.target.name, and
// omits source.* entirely (no remote endpoint involved).

static void test_sudo_local_brute_force_end_to_end(void **state) {
    (void)state;

    const char *log_line =
        "pam_unix(sudo:auth): authentication failure; logname= uid=1000 "
        "euid=0 tty=/dev/pts/0 ruser=dave rhost=  user=root";
    const uint64_t base_ts = 1700000000000000ULL;
    ps_pam_event_t breaching = {0};

    for (int i = 0; i < 3; i++) {
        breaching = parse_and_track(
            log_line, base_ts + (uint64_t)i * 1000000ULL, "devbox", 4242 + i);
    }

    assert_int_equal(fail_table_count, 1);
    assert_int_equal(fail_table[0].key_type, PS_FAIL_KEY_LOCAL_USER);
    assert_string_equal(fail_table[0].key, "dave");
    assert_string_equal(fail_table[0].target_username, "root");
    assert_int_equal(fail_table[0].service, PS_SERVICE_SUDO);
    assert_int_equal(fail_table[0].count, 0);

    char json[2048];
    format_local_brute_json(&g_config, fail_table[0].service, fail_table[0].key,
                            fail_table[0].target_username,
                            g_config.fail_threshold, g_config.fail_window_sec,
                            breaching.hostname, breaching.timestamp_usec,
                            breaching.pid, json, sizeof(json));

    assert_non_null(strstr(json, "\"action\":\"brute_force_detected\""));
    assert_non_null(strstr(json, "\"name\":\"dave\""));
    assert_non_null(strstr(json, "\"target\":{\"name\":\"root\"}"));
    assert_non_null(strstr(json, "\"service\":{\"name\":\"sudo\"}"));
    assert_non_null(strstr(json, "\"hostname\":\"devbox\""));
    assert_non_null(strstr(json, "\"attempts\":3"));
    // Local brute force has no remote endpoint.
    assert_null(strstr(json, "\"source\""));
}

// --- Scenario 4: Sudo invoked from an SSH session (rhost = IP) ---
//
// When sudo runs inside an SSH session, pam_unix puts the caller's IP in
// rhost. The parser must surface it as source_ip, and the tracker's
// derive_fail_key must then prefer the IP over the local-user fallback —
// otherwise an attacker who SSH'd in could evade IP-based brute-force
// correlation by pivoting to sudo.

static void test_sudo_with_rhost_is_ip_keyed(void **state) {
    (void)state;

    const char *log_line =
        "pam_unix(sudo:auth): authentication failure; logname= uid=1000 "
        "euid=0 tty=/dev/pts/0 ruser=dave rhost=10.0.0.50  user=root";
    const uint64_t base_ts = 1700000000000000ULL;

    for (int i = 0; i < 3; i++) {
        parse_and_track(log_line, base_ts + (uint64_t)i * 1000000ULL, "edge02",
                        6000);
    }

    assert_int_equal(fail_table_count, 1);
    assert_int_equal(fail_table[0].key_type, PS_FAIL_KEY_IP);
    assert_string_equal(fail_table[0].key, "10.0.0.50");
    // No accidental local-user entry created for the same line.
    for (int i = 0; i < fail_table_count; i++) {
        assert_int_not_equal(fail_table[i].key_type, PS_FAIL_KEY_LOCAL_USER);
    }
}

// --- Scenario 5: Interleaved attempts from two IPs ---
//
// Two attackers from different IPs must be tracked independently. Each IP's
// alert payload, generated from its own breaching event, must reference only
// its own address — no cross-contamination from the other entry.

static void test_multi_ip_interleaved_tracking(void **state) {
    (void)state;
    const uint64_t base_ts = 1700000000000000ULL;
    const char *line_a = "Failed password for root from 10.0.0.1 port 22 ssh2";
    const char *line_b = "Failed password for root from 10.0.0.2 port 22 ssh2";

    // Sequence: A B A B A (A breaches on its 3rd) ... B (B breaches on its 3rd)
    parse_and_track(line_a, base_ts + 0ULL, "h", 1);
    parse_and_track(line_b, base_ts + 1000000ULL, "h", 2);
    parse_and_track(line_a, base_ts + 2000000ULL, "h", 3);
    parse_and_track(line_b, base_ts + 3000000ULL, "h", 4);
    ps_pam_event_t breaching_a =
        parse_and_track(line_a, base_ts + 4000000ULL, "h", 5);

    assert_int_equal(fail_table_count, 2);

    int a_idx = -1, b_idx = -1;
    for (int i = 0; i < fail_table_count; i++) {
        if (strcmp(fail_table[i].key, "10.0.0.1") == 0)
            a_idx = i;
        else if (strcmp(fail_table[i].key, "10.0.0.2") == 0)
            b_idx = i;
    }
    assert_int_not_equal(a_idx, -1);
    assert_int_not_equal(b_idx, -1);
    assert_int_equal(fail_table[a_idx].count, 0); // A breached and reset
    assert_int_equal(fail_table[b_idx].count, 2); // B still below threshold

    ps_pam_event_t breaching_b =
        parse_and_track(line_b, base_ts + 5000000ULL, "h", 6);
    assert_int_equal(fail_table[b_idx].count, 0); // B breached and reset

    char json_a[2048];
    char json_b[2048];
    format_brute_json(&g_config, "10.0.0.1", g_config.fail_threshold,
                      g_config.fail_window_sec, breaching_a.username,
                      breaching_a.hostname, breaching_a.timestamp_usec,
                      breaching_a.pid, json_a, sizeof(json_a));
    format_brute_json(&g_config, "10.0.0.2", g_config.fail_threshold,
                      g_config.fail_window_sec, breaching_b.username,
                      breaching_b.hostname, breaching_b.timestamp_usec,
                      breaching_b.pid, json_b, sizeof(json_b));

    assert_non_null(strstr(json_a, "\"ip\":\"10.0.0.1\""));
    assert_null(strstr(json_a, "10.0.0.2"));
    assert_non_null(strstr(json_b, "\"ip\":\"10.0.0.2\""));
    assert_null(strstr(json_b, "10.0.0.1"));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ssh_brute_force_ipv4_end_to_end,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_ssh_brute_force_ipv6_end_to_end,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sudo_local_brute_force_end_to_end,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sudo_with_rhost_is_ip_keyed, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_multi_ip_interleaved_tracking,
                                        setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
