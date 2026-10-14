/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "defenseclaw.h"
#include "platform.h"

extern dclaw_state_t *dclaw_get_state(void);

static void refill_tokens(dclaw_rate_limiter_t *rl) {
    uint64_t now = hal_tick_ms();
    uint64_t elapsed_ms = now - rl->last_refill_tick;

    if (elapsed_ms < 1000) return; /* Refill at most once per second */

    uint64_t elapsed_sec = elapsed_ms / 1000;
    uint64_t new_tokens = (rl->refill_rate * elapsed_sec) / 60;

    if (new_tokens > 0) {
        uint32_t sum = (uint32_t)rl->tokens + (uint32_t)new_tokens;
        rl->tokens = (sum > rl->bucket_size)
                     ? rl->bucket_size
                     : (uint16_t)sum;
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
