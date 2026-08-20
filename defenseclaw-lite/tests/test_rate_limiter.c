#include "defenseclaw.h"
#include "platform.h"
#include <stdio.h>
#include <assert.h>

extern bool dclaw_rate_limit_check(uint8_t cap_flags);
extern dclaw_state_t *dclaw_get_state(void);

static void test_allows_under_limit(void) {
    assert(dclaw_rate_limit_check(DCLAW_CAP_READ_FS) == true);
    printf("  PASS: under limit -> allowed\n");
}

static void test_global_limit_exhaustion(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->rate_limiters[0].tokens = 1; /* last token */

    assert(dclaw_rate_limit_check(DCLAW_CAP_READ_FS) == true);
    assert(dclaw_rate_limit_check(DCLAW_CAP_READ_FS) == false); /* exhausted */
    printf("  PASS: global limit exhaustion -> reject\n");

    /* Restore */
    s->rate_limiters[0].tokens = 60;
}

static void test_network_limit(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->rate_limiters[1].tokens = 1;

    assert(dclaw_rate_limit_check(DCLAW_CAP_NET_FETCH) == true);
    assert(dclaw_rate_limit_check(DCLAW_CAP_NET_FETCH) == false);
    printf("  PASS: network limit exhaustion -> reject\n");

    s->rate_limiters[1].tokens = 30;
}

static void test_actuate_limit(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->rate_limiters[2].tokens = 1;

    assert(dclaw_rate_limit_check(DCLAW_CAP_ACTUATE) == true);
    assert(dclaw_rate_limit_check(DCLAW_CAP_ACTUATE) == false);
    printf("  PASS: actuation limit exhaustion -> reject\n");

    s->rate_limiters[2].tokens = 10;
}

static void test_non_network_doesnt_consume_network_tokens(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint16_t net_tokens_before = s->rate_limiters[1].tokens;

    dclaw_rate_limit_check(DCLAW_CAP_READ_FS);

    assert(s->rate_limiters[1].tokens == net_tokens_before);
    printf("  PASS: READ_FS doesn't consume network tokens\n");
}

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 1};
    dclaw_init(&info);

    printf("test_rate_limiter:\n");
    test_allows_under_limit();
    test_global_limit_exhaustion();
    test_network_limit();
    test_actuate_limit();
    test_non_network_doesnt_consume_network_tokens();
    printf("  ALL PASSED (5 tests)\n");

    dclaw_shutdown();
    return 0;
}
