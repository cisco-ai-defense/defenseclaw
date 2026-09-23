#include "defenseclaw.h"
#include "platform.h"

extern dclaw_state_t *dclaw_get_state(void);

static void refill_tokens(dclaw_rate_limiter_t *rl) {
    uint32_t now = hal_tick_ms();
    uint32_t elapsed_ms = now - rl->last_refill_tick;

    if (elapsed_ms < 1000) return; /* Refill at most once per second */

    uint32_t elapsed_sec = elapsed_ms / 1000;
    uint32_t new_tokens = (rl->refill_rate * elapsed_sec) / 60;

    if (new_tokens > 0) {
        rl->tokens = (rl->tokens + (uint16_t)new_tokens > rl->bucket_size)
                     ? rl->bucket_size
                     : rl->tokens + (uint16_t)new_tokens;
        rl->last_refill_tick = now;
    }
}

bool dclaw_rate_limit_check(uint8_t cap_flags) {
    dclaw_state_t *s = dclaw_get_state();

    /* Limiter 0: global (all tool calls) */
    refill_tokens(&s->rate_limiters[0]);
    if (s->rate_limiters[0].tokens == 0) return false;

    /* Limiter 1: network (NET_FETCH | SEND_MSG) */
    if (cap_flags & (DCLAW_CAP_NET_FETCH | DCLAW_CAP_SEND_MSG)) {
        refill_tokens(&s->rate_limiters[1]);
        if (s->rate_limiters[1].tokens == 0) return false;
        s->rate_limiters[1].tokens--;
    }

    /* Limiter 2: actuations (ACTUATE) */
    if (cap_flags & DCLAW_CAP_ACTUATE) {
        refill_tokens(&s->rate_limiters[2]);
        if (s->rate_limiters[2].tokens == 0) return false;
        s->rate_limiters[2].tokens--;
    }

    s->rate_limiters[0].tokens--;
    return true;
}
