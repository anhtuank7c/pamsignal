// Tests for the brute-force tracker in journal_watch.c.
//
// We #include the source file directly so the suite can inspect file-static
// state (fail_table, fail_table_count, fail_table_capacity) and call the
// file-static ps_track_failed_login helper without having to expose them in
// the public header. The matching meson target therefore must NOT also link
// src/journal_watch.c — that would yield duplicate symbols.

#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

// Stubs for the signal-handler flags defined in init.c. The tests never
// invoke ps_journal_watch_run() (which is the only consumer), but the linker
// still wants definitions for these externs referenced through init.h.
volatile sig_atomic_t running = 0;
volatile sig_atomic_t reload_requested = 0;

// Include-the-source-file pattern lets us drive file-static fail_table state
// and ps_track_failed_login without exposing them in the public header.
// NOLINTNEXTLINE(bugprone-suspicious-include)
#include "../src/journal_watch.c"

// --- Fixtures ---

static void setup_config(int threshold, int window_sec, int max_ips,
                         int cooldown_sec) {
    ps_config_defaults(&g_config);
    g_config.fail_threshold = threshold;
    g_config.fail_window_sec = window_sec;
    g_config.max_tracked_ips = max_ips;
    g_config.alert_cooldown_sec = cooldown_sec;
}

static ps_pam_event_t make_failed_login(const char *ip, const char *user,
                                        uint64_t ts_usec) {
    ps_pam_event_t e;
    memset(&e, 0, sizeof(e));
    e.type = PS_EVENT_LOGIN_FAILED;
    e.auth_method = PS_AUTH_PASSWORD;
    e.service = PS_SERVICE_SSHD;
    snprintf(e.username, sizeof(e.username), "%s", user);
    snprintf(e.source_ip, sizeof(e.source_ip), "%s", ip);
    e.timestamp_usec = ts_usec;
    return e;
}

// sudo/su auth-failure event with no rhost. The tracker keys on ruser
// (event.username) when service is sudo/su and source_ip is empty.
static ps_pam_event_t make_failed_sudo(const char *actor, const char *target,
                                       uint64_t ts_usec) {
    ps_pam_event_t e;
    memset(&e, 0, sizeof(e));
    e.type = PS_EVENT_LOGIN_FAILED;
    e.auth_method = PS_AUTH_PASSWORD;
    e.service = PS_SERVICE_SUDO;
    snprintf(e.username, sizeof(e.username), "%s", actor);
    snprintf(e.target_username, sizeof(e.target_username), "%s", target);
    e.timestamp_usec = ts_usec;
    return e;
}

static int teardown(void **state) {
    (void)state;
    free(fail_table);
    fail_table = NULL;
    fail_table_count = 0;
    fail_table_capacity = 0;
    return 0;
}

// --- ps_fail_table_init ---

static void test_init_zero_capacity_rejected(void **state) {
    (void)state;
    assert_int_equal(ps_fail_table_init(0), PS_ERR_INIT);
}

static void test_init_negative_capacity_rejected(void **state) {
    (void)state;
    assert_int_equal(ps_fail_table_init(-1), PS_ERR_INIT);
}

static void test_init_positive_capacity(void **state) {
    (void)state;
    assert_int_equal(ps_fail_table_init(8), PS_OK);
    assert_non_null(fail_table);
    assert_int_equal(fail_table_capacity, 8);
    assert_int_equal(fail_table_count, 0);
}

static void test_init_preserves_previous_table(void **state) {
    (void)state;
    assert_int_equal(ps_fail_table_init(4), PS_OK);
    setup_config(3, 60, 4, 0);
    ps_pam_event_t e = make_failed_login("192.0.2.1", "alice", 1000000);
    ps_track_failed_login(&e);
    assert_int_equal(fail_table_count, 1);

    // Reinit with a different capacity must preserve the table.
    assert_int_equal(ps_fail_table_init(16), PS_OK);
    assert_int_equal(fail_table_capacity, 16);
    assert_int_equal(fail_table_count, 1);
    assert_string_equal(fail_table[0].key, "192.0.2.1");
}

// --- ps_track_failed_login: counting ---

static void test_track_first_attempt_creates_entry(void **state) {
    (void)state;
    setup_config(5, 60, 8, 0);
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    ps_pam_event_t e = make_failed_login("192.0.2.1", "alice", 1000000);
    ps_track_failed_login(&e);

    assert_int_equal(fail_table_count, 1);
    assert_string_equal(fail_table[0].key, "192.0.2.1");
    assert_int_equal(fail_table[0].count, 1);
    assert_int_equal(fail_table[0].first_attempt_usec, 1000000);
}

static void test_track_increments_for_same_ip(void **state) {
    (void)state;
    setup_config(5, 60, 8, 0);
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    for (int i = 0; i < 3; i++) {
        ps_pam_event_t e = make_failed_login(
            "192.0.2.1", "alice", 1000000ULL + (uint64_t)i * 1000000);
        ps_track_failed_login(&e);
    }

    assert_int_equal(fail_table_count, 1);
    assert_int_equal(fail_table[0].count, 3);
}

static void test_track_separates_ips(void **state) {
    (void)state;
    setup_config(5, 60, 8, 0);
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    ps_pam_event_t e1 = make_failed_login("192.0.2.1", "alice", 1000000);
    ps_pam_event_t e2 = make_failed_login("192.0.2.2", "bob", 2000000);
    ps_pam_event_t e3 = make_failed_login("192.0.2.1", "alice", 3000000);

    ps_track_failed_login(&e1);
    ps_track_failed_login(&e2);
    ps_track_failed_login(&e3);

    assert_int_equal(fail_table_count, 2);
    // Order matches insertion: 192.0.2.1 first.
    assert_string_equal(fail_table[0].key, "192.0.2.1");
    assert_int_equal(fail_table[0].count, 2);
    assert_string_equal(fail_table[1].key, "192.0.2.2");
    assert_int_equal(fail_table[1].count, 1);
}

static void test_track_skips_empty_ip(void **state) {
    (void)state;
    setup_config(5, 60, 8, 0);
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    ps_pam_event_t e = make_failed_login("", "alice", 1000000);
    ps_track_failed_login(&e);

    assert_int_equal(fail_table_count, 0);
}

// --- ps_track_failed_login: window expiration ---

static void test_track_window_expires_resets_counter(void **state) {
    (void)state;
    setup_config(5, 60, 8, 0); // 60-second window
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    uint64_t t0 = 1000000;
    uint64_t t_outside_window = t0 + (61ULL * 1000000); // 61 seconds later

    ps_pam_event_t e1 = make_failed_login("192.0.2.1", "alice", t0);
    ps_pam_event_t e2 = make_failed_login("192.0.2.1", "alice", t0 + 1000000);
    ps_pam_event_t e3 =
        make_failed_login("192.0.2.1", "alice", t_outside_window);

    ps_track_failed_login(&e1);
    ps_track_failed_login(&e2);
    assert_int_equal(fail_table[0].count, 2);

    ps_track_failed_login(&e3);
    // Window expired: counter restarts at 1 with first_attempt = e3 time.
    assert_int_equal(fail_table[0].count, 1);
    assert_int_equal(fail_table[0].first_attempt_usec, t_outside_window);
}

// --- Threshold + per-IP cooldown ---

static void test_track_threshold_resets_count_and_arms_cooldown(void **state) {
    (void)state;
    setup_config(3, 60, 8, 60);
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    uint64_t t0 = 1000000;
    for (int i = 0; i < 3; i++) {
        ps_pam_event_t e =
            make_failed_login("192.0.2.1", "alice", t0 + (uint64_t)i * 1000000);
        ps_track_failed_login(&e);
    }

    // Threshold reached: count is reset to 0 and the cooldown timestamp is
    // armed at the breaching event's timestamp.
    assert_int_equal(fail_table[0].count, 0);
    assert_int_equal(fail_table[0].last_brute_alert_usec, t0 + 2ULL * 1000000);
    assert_int_equal(fail_table[0].first_attempt_usec, t0 + 2ULL * 1000000);
}

static void test_track_per_ip_cooldown_suppresses_repeat_alert(void **state) {
    (void)state;
    setup_config(2, 60, 8, 60); // threshold=2, cooldown=60s
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    uint64_t t0 = 1000000;
    // First breach.
    ps_pam_event_t e1 = make_failed_login("192.0.2.1", "alice", t0);
    ps_pam_event_t e2 = make_failed_login("192.0.2.1", "alice", t0 + 1000000);
    ps_track_failed_login(&e1);
    ps_track_failed_login(&e2);
    uint64_t alert_ts_after_first_breach = fail_table[0].last_brute_alert_usec;
    assert_int_equal(alert_ts_after_first_breach, t0 + 1000000);

    // Two more attempts well within cooldown (10s later) — second breach.
    uint64_t t_within_cooldown = t0 + 10ULL * 1000000;
    ps_pam_event_t e3 =
        make_failed_login("192.0.2.1", "alice", t_within_cooldown);
    ps_pam_event_t e4 =
        make_failed_login("192.0.2.1", "alice", t_within_cooldown + 1000000);
    ps_track_failed_login(&e3);
    ps_track_failed_login(&e4);

    // Cooldown gate held: last_brute_alert_usec must NOT have advanced.
    assert_int_equal(fail_table[0].last_brute_alert_usec,
                     alert_ts_after_first_breach);
}

static void test_track_per_ip_cooldown_releases_after_window(void **state) {
    (void)state;
    setup_config(2, 600, 8, 60); // threshold=2, cooldown=60s
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    uint64_t t0 = 1000000;
    ps_track_failed_login(&(ps_pam_event_t){.type = PS_EVENT_LOGIN_FAILED,
                                            .source_ip = "192.0.2.1",
                                            .timestamp_usec = t0});
    ps_track_failed_login(&(ps_pam_event_t){.type = PS_EVENT_LOGIN_FAILED,
                                            .source_ip = "192.0.2.1",
                                            .timestamp_usec = t0 + 1000000});
    uint64_t first_alert = fail_table[0].last_brute_alert_usec;

    // Breach again outside cooldown window (61s later).
    uint64_t t_after_cooldown = t0 + 61ULL * 1000000;
    ps_track_failed_login(
        &(ps_pam_event_t){.type = PS_EVENT_LOGIN_FAILED,
                          .source_ip = "192.0.2.1",
                          .timestamp_usec = t_after_cooldown});
    ps_track_failed_login(
        &(ps_pam_event_t){.type = PS_EVENT_LOGIN_FAILED,
                          .source_ip = "192.0.2.1",
                          .timestamp_usec = t_after_cooldown + 1000000});

    // Cooldown released: last_brute_alert_usec advanced to the new breach.
    assert_int_not_equal(fail_table[0].last_brute_alert_usec, first_alert);
    assert_int_equal(fail_table[0].last_brute_alert_usec,
                     t_after_cooldown + 1000000);
}

// --- Eviction when capacity full ---

static void test_track_evicts_oldest_when_full(void **state) {
    (void)state;
    setup_config(10, 600, 3, 0); // capacity = 3
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    uint64_t t = 1000000;
    ps_pam_event_t e1 = make_failed_login("192.0.2.1", "a", t);
    ps_pam_event_t e2 = make_failed_login("192.0.2.2", "b", t + 1000000);
    ps_pam_event_t e3 = make_failed_login("192.0.2.3", "c", t + 2000000);
    ps_track_failed_login(&e1);
    ps_track_failed_login(&e2);
    ps_track_failed_login(&e3);
    assert_int_equal(fail_table_count, 3);

    // Touch entry 0 so its last_attempt is fresher than entries 1 and 2.
    ps_pam_event_t e1_again = make_failed_login("192.0.2.1", "a", t + 3000000);
    ps_track_failed_login(&e1_again);

    // New IP arrives — table is full, oldest by last_attempt_usec is 192.0.2.2.
    ps_pam_event_t e4 = make_failed_login("192.0.2.4", "d", t + 4000000);
    ps_track_failed_login(&e4);

    // Capacity unchanged; 192.0.2.2 must be gone.
    assert_int_equal(fail_table_count, 3);
    int found_evicted_victim = 0;
    int found_new_entry = 0;
    for (int i = 0; i < fail_table_count; i++) {
        if (strcmp(fail_table[i].key, "192.0.2.2") == 0)
            found_evicted_victim = 1;
        if (strcmp(fail_table[i].key, "192.0.2.4") == 0)
            found_new_entry = 1;
    }
    assert_int_equal(found_evicted_victim, 0);
    assert_int_equal(found_new_entry, 1);
}

// --- ps_track_failed_login: sudo/su local-actor path ---

static void test_track_sudo_first_attempt_creates_local_entry(void **state) {
    (void)state;
    setup_config(5, 60, 8, 0);
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    ps_pam_event_t e = make_failed_sudo("alice", "root", 1000000);
    ps_track_failed_login(&e);

    assert_int_equal(fail_table_count, 1);
    assert_int_equal(fail_table[0].key_type, PS_FAIL_KEY_LOCAL_USER);
    assert_string_equal(fail_table[0].key, "alice");
    assert_string_equal(fail_table[0].target_username, "root");
    assert_int_equal(fail_table[0].service, PS_SERVICE_SUDO);
    assert_int_equal(fail_table[0].count, 1);
}

static void test_track_sudo_increments_for_same_actor(void **state) {
    (void)state;
    setup_config(5, 60, 8, 0);
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    for (int i = 0; i < 4; i++) {
        ps_pam_event_t e = make_failed_sudo("alice", "root",
                                            1000000ULL + (uint64_t)i * 1000000);
        ps_track_failed_login(&e);
    }

    assert_int_equal(fail_table_count, 1);
    assert_int_equal(fail_table[0].count, 4);
}

// An IP "alice" (contrived but legal as a string) and a sudo actor "alice"
// share their string but key_type makes them distinct entries. This guards
// against a future regression where the tuple comparison drops to
// string-only.
static void test_track_ip_and_local_user_do_not_collide(void **state) {
    (void)state;
    setup_config(5, 60, 8, 0);
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    ps_pam_event_t ip_event = make_failed_login("alice", "root", 1000000);
    // Bypass is_valid_ip on the synthetic IP — make_failed_login already
    // copied it verbatim, and ps_track_failed_login doesn't re-validate.
    ps_pam_event_t sudo_event = make_failed_sudo("alice", "root", 2000000);

    ps_track_failed_login(&ip_event);
    ps_track_failed_login(&sudo_event);

    assert_int_equal(fail_table_count, 2);

    int saw_ip = 0, saw_local = 0;
    for (int i = 0; i < fail_table_count; i++) {
        if (fail_table[i].key_type == PS_FAIL_KEY_IP &&
            strcmp(fail_table[i].key, "alice") == 0)
            saw_ip = 1;
        if (fail_table[i].key_type == PS_FAIL_KEY_LOCAL_USER &&
            strcmp(fail_table[i].key, "alice") == 0)
            saw_local = 1;
    }
    assert_int_equal(saw_ip, 1);
    assert_int_equal(saw_local, 1);
}

static void test_track_sudo_threshold_resets_and_arms_cooldown(void **state) {
    (void)state;
    setup_config(3, 60, 8, 60);
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    uint64_t t0 = 1000000;
    for (int i = 0; i < 3; i++) {
        ps_pam_event_t e =
            make_failed_sudo("alice", "root", t0 + (uint64_t)i * 1000000);
        ps_track_failed_login(&e);
    }

    // Threshold (3) crossed → count zeroed, cooldown armed, alert fired.
    assert_int_equal(fail_table_count, 1);
    assert_int_equal(fail_table[0].count, 0);
    assert_int_not_equal(fail_table[0].last_brute_alert_usec, 0);
}

// Empty username AND empty source IP for a sudo event must be skipped — the
// derive_fail_key contract is "must have a trackable identity."
static void test_track_skips_sudo_without_actor(void **state) {
    (void)state;
    setup_config(5, 60, 8, 0);
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    ps_pam_event_t e;
    memset(&e, 0, sizeof(e));
    e.type = PS_EVENT_LOGIN_FAILED;
    e.service = PS_SERVICE_SUDO;
    e.timestamp_usec = 1000000;
    // username and source_ip both empty.
    ps_track_failed_login(&e);

    assert_int_equal(fail_table_count, 0);
}

// Sudo with rhost-as-IP exercises the IP path (via derive_fail_key), even
// though the service is sudo. The entry's key_type is IP and the alert
// payload would carry source.ip (the SSH→sudo chain case).
static void test_track_sudo_with_ip_keys_by_ip(void **state) {
    (void)state;
    setup_config(5, 60, 8, 0);
    assert_int_equal(ps_fail_table_init(g_config.max_tracked_ips), PS_OK);

    ps_pam_event_t e = make_failed_sudo("alice", "root", 1000000);
    snprintf(e.source_ip, sizeof(e.source_ip), "%s", "192.0.2.5");
    ps_track_failed_login(&e);

    assert_int_equal(fail_table_count, 1);
    assert_int_equal(fail_table[0].key_type, PS_FAIL_KEY_IP);
    assert_string_equal(fail_table[0].key, "192.0.2.5");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_init_zero_capacity_rejected, teardown),
        cmocka_unit_test_teardown(test_init_negative_capacity_rejected,
                                  teardown),
        cmocka_unit_test_teardown(test_init_positive_capacity, teardown),
        cmocka_unit_test_teardown(test_init_preserves_previous_table, teardown),
        cmocka_unit_test_teardown(test_track_first_attempt_creates_entry,
                                  teardown),
        cmocka_unit_test_teardown(test_track_increments_for_same_ip, teardown),
        cmocka_unit_test_teardown(test_track_separates_ips, teardown),
        cmocka_unit_test_teardown(test_track_skips_empty_ip, teardown),
        cmocka_unit_test_teardown(test_track_window_expires_resets_counter,
                                  teardown),
        cmocka_unit_test_teardown(
            test_track_threshold_resets_count_and_arms_cooldown, teardown),
        cmocka_unit_test_teardown(
            test_track_per_ip_cooldown_suppresses_repeat_alert, teardown),
        cmocka_unit_test_teardown(
            test_track_per_ip_cooldown_releases_after_window, teardown),
        cmocka_unit_test_teardown(test_track_evicts_oldest_when_full, teardown),
        cmocka_unit_test_teardown(
            test_track_sudo_first_attempt_creates_local_entry, teardown),
        cmocka_unit_test_teardown(test_track_sudo_increments_for_same_actor,
                                  teardown),
        cmocka_unit_test_teardown(test_track_ip_and_local_user_do_not_collide,
                                  teardown),
        cmocka_unit_test_teardown(
            test_track_sudo_threshold_resets_and_arms_cooldown, teardown),
        cmocka_unit_test_teardown(test_track_skips_sudo_without_actor,
                                  teardown),
        cmocka_unit_test_teardown(test_track_sudo_with_ip_keys_by_ip, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
