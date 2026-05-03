// Tests for the notify dispatch path. The interesting helpers in notify.c
// (json_escape, fire_curl, build_secrets_memfd) are static, and the public
// API forks curl, so these are smoke tests that exercise the no-op /
// disabled-channel paths and the cooldown logic without spawning children.

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "config.h"
#include "notify.h"
#include "pam_event.h"

static void make_event(ps_pam_event_t *e) {
    memset(e, 0, sizeof(*e));
    e->type = PS_EVENT_LOGIN_FAILED;
    e->auth_method = PS_AUTH_PASSWORD;
    e->service = PS_SERVICE_SSHD;
    strncpy(e->username, "alice", sizeof(e->username) - 1);
    strncpy(e->source_ip, "192.0.2.1", sizeof(e->source_ip) - 1);
    e->port = 22;
    strncpy(e->hostname, "host", sizeof(e->hostname) - 1);
    e->timestamp_usec = 1700000000000000ULL;
}

// With no channels configured, ps_notify_event must be a no-op (no fork).
static void test_notify_event_no_channels(void **state) {
    (void)state;
    ps_config_t cfg;
    ps_config_defaults(&cfg);

    ps_pam_event_t e;
    make_event(&e);

    // Should not crash, should not fork. Asserting absence of side effects
    // would require process introspection; we rely on the channel checks in
    // each sender returning early when their config fields are empty.
    ps_notify_event(&cfg, &e);
}

// Same for brute-force notifications.
static void test_notify_brute_no_channels(void **state) {
    (void)state;
    ps_config_t cfg;
    ps_config_defaults(&cfg);

    ps_notify_brute_force(&cfg, "192.0.2.99", 5, 60, "alice", "host",
                          1700000000000000ULL, 12345);
}

// And for the local (sudo/su) brute-force variant.
static void test_notify_local_brute_no_channels(void **state) {
    (void)state;
    ps_config_t cfg;
    ps_config_defaults(&cfg);

    ps_notify_local_brute_force(&cfg, PS_SERVICE_SUDO, "alice", "root", 5, 60,
                                "host", 1700000000000000ULL, 12345);
}

// Cooldown: with a long cooldown, only the first invocation should attempt
// dispatch. The second should be suppressed by is_cooled_down(). Without
// channels configured, both calls remain no-ops; the test asserts the
// public API tolerates being called repeatedly under cooldown.
static void test_notify_event_cooldown_repeat(void **state) {
    (void)state;
    ps_config_t cfg;
    ps_config_defaults(&cfg);
    cfg.alert_cooldown_sec = 3600;

    ps_pam_event_t e;
    make_event(&e);

    ps_notify_event(&cfg, &e);
    ps_notify_event(&cfg, &e);
    ps_notify_event(&cfg, &e);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_notify_event_no_channels),
        cmocka_unit_test(test_notify_brute_no_channels),
        cmocka_unit_test(test_notify_local_brute_no_channels),
        cmocka_unit_test(test_notify_event_cooldown_repeat),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
