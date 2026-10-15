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
#include <string.h>

extern dclaw_state_t *dclaw_get_state(void);

#if DCLAW_VERDICT_CACHE_SIZE > 0

/* Local defaults and maximum accepted signed TTLs, in minutes. Cloud ALLOW
 * is bounded to one hour even if a peer signs an excessive lifetime. */
static uint16_t ttl_for_action(dclaw_action_t action) {
    switch (action) {
    case DCLAW_ACTION_ALLOW: return 24 * 60;
    case DCLAW_ACTION_BLOCK: return 7 * 24 * 60;
    case DCLAW_ACTION_WARN:  return 4 * 60;
    default: return 0;
    }
}

static bool is_expired(const dclaw_cache_entry_t *entry) {
    /* Use monotonic ticks (hal_tick_ms) for TTL computation instead of
     * wall-clock time. cached_at_tick is already a monotonic timestamp,
     * so the cache works correctly regardless of time_trusted state.
     * Removes the previous time_trusted guard that disabled the entire
     * cache before the first clock sync, causing unnecessary cache misses. */
    uint64_t now = hal_tick_ms();
    uint64_t elapsed_min = (now - entry->cached_at_tick) / 60000;
    return elapsed_min >= entry->ttl_minutes;
}

static size_t find_lru_slot(const uint8_t *tool_hash) {
    dclaw_state_t *s = dclaw_get_state();
    size_t lru_idx = 0;
    size_t empty_idx = DCLAW_VERDICT_CACHE_SIZE;
    uint64_t lru_tick = UINT64_MAX;

    for (size_t i = 0; i < DCLAW_VERDICT_CACHE_SIZE; i++) {
        if (s->cache[i].occupied && memcmp(s->cache[i].tool_hash, tool_hash, 32) == 0)
            return i; /* Replace a previous decision for this tool. */
        if (!s->cache[i].occupied) {
            if (empty_idx == DCLAW_VERDICT_CACHE_SIZE) empty_idx = i;
        } else if (s->cache[i].cached_at_tick < lru_tick) {
            lru_tick = s->cache[i].cached_at_tick;
            lru_idx = i;
        }
    }
    return empty_idx < DCLAW_VERDICT_CACHE_SIZE ? empty_idx : lru_idx;
}

static void cache_store_entry(const uint8_t *tool_hash, dclaw_action_t action,
                              dclaw_severity_t severity, uint16_t ttl_minutes) {
    dclaw_state_t *s = dclaw_get_state();
    size_t idx = find_lru_slot(tool_hash);
    /* Older cache writers could create duplicate entries for one hash.
     * Clear every other copy so a stale ALLOW cannot resurface later. */
    for (size_t i = 0; i < DCLAW_VERDICT_CACHE_SIZE; i++) {
        if (i != idx && s->cache[i].occupied &&
            memcmp(s->cache[i].tool_hash, tool_hash, 32) == 0)
            s->cache[i].occupied = false;
    }
    if (ttl_minutes == 0) {
        /* A signed zero TTL revokes any previous cached answer for the tool. */
        if (s->cache[idx].occupied && memcmp(s->cache[idx].tool_hash, tool_hash, 32) == 0)
            s->cache[idx].occupied = false;
        return;
    }

    memcpy(s->cache[idx].tool_hash, tool_hash, 32);
    s->cache[idx].action = (uint8_t)action;
    s->cache[idx].severity = (uint8_t)severity;
    /* Keep the reserved public state fields deterministic until a separate
     * ABI revision can remove them. Verdicts carry no evidence snippet. */
    s->cache[idx].category = 0;
    memset(s->cache[idx].evidence, 0, sizeof(s->cache[idx].evidence));

    s->cache[idx].ttl_minutes = ttl_minutes;
    s->cache[idx].cached_at_tick = hal_tick_ms();
    s->cache[idx].occupied = true;
}

#endif /* DCLAW_VERDICT_CACHE_SIZE > 0 */

bool dclaw_cache_lookup(const uint8_t *tool_hash, dclaw_verdict_t *out) {
#if DCLAW_VERDICT_CACHE_SIZE == 0
    (void)tool_hash; (void)out;
    return false;
#else
    dclaw_state_t *s = dclaw_get_state();

    for (size_t i = 0; i < DCLAW_VERDICT_CACHE_SIZE; i++) {
        if (!s->cache[i].occupied) continue;
        if (memcmp(s->cache[i].tool_hash, tool_hash, 32) != 0) continue;

        if (is_expired(&s->cache[i])) {
            s->cache[i].occupied = false;
            return false;
        }

        out->action = (dclaw_action_t)s->cache[i].action;
        out->severity = (dclaw_severity_t)s->cache[i].severity;
        out->ttl_minutes = s->cache[i].ttl_minutes;
        out->reason = DCLAW_REASON_CLOUD_BLOCK; /* cached cloud decision */
        out->mode = DCLAW_VERDICT_SYNC;
        out->from_cache = true;
        return true;
    }
    return false;
#endif /* DCLAW_VERDICT_CACHE_SIZE */
}

void dclaw_cache_store_with_ttl(const uint8_t *tool_hash, dclaw_action_t action,
                                dclaw_severity_t severity, uint16_t ttl_minutes) {
#if DCLAW_VERDICT_CACHE_SIZE == 0
    (void)tool_hash; (void)action; (void)severity; (void)ttl_minutes;
#else
    uint16_t ceiling = ttl_for_action(action);
    if (action == DCLAW_ACTION_ALLOW && ceiling > 60) ceiling = 60;
    if (ttl_minutes > ceiling) ttl_minutes = ceiling;
    cache_store_entry(tool_hash, action, severity, ttl_minutes);
#endif
}

void dclaw_cache_invalidate(const uint8_t *tool_hash) {
#if DCLAW_VERDICT_CACHE_SIZE == 0
    (void)tool_hash;
#else
    dclaw_state_t *s = dclaw_get_state();
    for (size_t i = 0; i < DCLAW_VERDICT_CACHE_SIZE; i++) {
        if (s->cache[i].occupied && memcmp(s->cache[i].tool_hash, tool_hash, 32) == 0) {
            s->cache[i].occupied = false;
        }
    }
#endif
}

void dclaw_cache_flush_all(void) {
#if DCLAW_VERDICT_CACHE_SIZE == 0
    return;
#else
    dclaw_state_t *s = dclaw_get_state();
    for (size_t i = 0; i < DCLAW_VERDICT_CACHE_SIZE; i++) {
        s->cache[i].occupied = false;
    }
#endif
}
