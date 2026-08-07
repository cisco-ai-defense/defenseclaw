#include "defenseclaw.h"
#include "platform.h"
#include <string.h>

extern dclaw_state_t *dclaw_get_state(void);

static uint32_t ttl_for_action(dclaw_action_t action) {
    switch (action) {
    case DCLAW_ACTION_ALLOW: return 24 * 60;  /* 24 hours */
    case DCLAW_ACTION_BLOCK: return 7 * 24 * 60; /* 7 days */
    case DCLAW_ACTION_WARN:  return 4 * 60;   /* 4 hours */
    default: return 0;
    }
}

static bool is_expired(const dclaw_cache_entry_t *entry) {
    dclaw_state_t *s = dclaw_get_state();
    if (!s->clock.time_trusted) return true; /* Conservative: all expired if clock untrusted */

    uint32_t now = hal_tick_ms();
    uint32_t elapsed_min = (now - entry->cached_at_tick) / 60000;
    return elapsed_min >= entry->ttl_minutes;
}

static size_t find_lru_slot(void) {
    dclaw_state_t *s = dclaw_get_state();
    size_t lru_idx = 0;
    uint32_t lru_tick = UINT32_MAX;

    for (size_t i = 0; i < DCLAW_VERDICT_CACHE_SIZE; i++) {
        if (!s->cache[i].occupied) return i;
        if (s->cache[i].cached_at_tick < lru_tick) {
            lru_tick = s->cache[i].cached_at_tick;
            lru_idx = i;
        }
    }
    return lru_idx;
}

bool dclaw_cache_lookup(const uint8_t *tool_hash, dclaw_verdict_t *out) {
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
}

void dclaw_cache_store(const uint8_t *tool_hash, dclaw_action_t action,
                       dclaw_severity_t severity) {
    dclaw_state_t *s = dclaw_get_state();
    size_t idx = find_lru_slot();

    memcpy(s->cache[idx].tool_hash, tool_hash, 32);
    s->cache[idx].action = (uint8_t)action;
    s->cache[idx].severity = (uint8_t)severity;
    s->cache[idx].ttl_minutes = (uint16_t)ttl_for_action(action);
    s->cache[idx].cached_at_tick = hal_tick_ms();
    s->cache[idx].occupied = true;
}

void dclaw_cache_invalidate(const uint8_t *tool_hash) {
    dclaw_state_t *s = dclaw_get_state();
    for (size_t i = 0; i < DCLAW_VERDICT_CACHE_SIZE; i++) {
        if (s->cache[i].occupied && memcmp(s->cache[i].tool_hash, tool_hash, 32) == 0) {
            s->cache[i].occupied = false;
            return;
        }
    }
}

void dclaw_cache_flush_all(void) {
    dclaw_state_t *s = dclaw_get_state();
    for (size_t i = 0; i < DCLAW_VERDICT_CACHE_SIZE; i++) {
        s->cache[i].occupied = false;
    }
}
