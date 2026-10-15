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
#include <stdio.h>
#include <string.h>
#include <assert.h>

#if DCLAW_VERDICT_CACHE_SIZE == 0
/* MINIMAL profile has no cache — the CMakeLists.txt guard should prevent
 * this file from being compiled, but if it is reached anyway provide a
 * no-op main so the build does not fail (P1-03 fix). */
int main(void) {
    printf("test_verdict_cache: SKIPPED (DCLAW_VERDICT_CACHE_SIZE == 0)\n");
    return 0;
}
#else /* DCLAW_VERDICT_CACHE_SIZE > 0 */

extern bool dclaw_cache_lookup(const uint8_t *tool_hash, dclaw_verdict_t *out);
extern void dclaw_cache_store_with_ttl(const uint8_t *tool_hash, dclaw_action_t action,
                                       dclaw_severity_t severity, uint16_t ttl_minutes);
extern void dclaw_cache_invalidate(const uint8_t *tool_hash);
extern void dclaw_cache_flush_all(void);
extern dclaw_state_t *dclaw_get_state(void);

static void make_hash(uint8_t *hash, uint8_t seed) {
    memset(hash, seed, 32);
}

static void test_miss_on_empty(void) {
    uint8_t hash[32];
    make_hash(hash, 0xAA);
    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(hash, &v) == false);
    (void)v;
    printf("  PASS: lookup on empty cache returns miss\n");
}

static void test_store_and_hit(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->clock.time_trusted = true;

    uint8_t hash[32];
    make_hash(hash, 0xBB);
    dclaw_cache_store_with_ttl(hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO, 60);

    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(hash, &v) == true);
    assert(v.action == DCLAW_ACTION_ALLOW);
    assert(v.from_cache == true);
    (void)v;
    printf("  PASS: store + lookup returns cached verdict\n");
}

static void test_different_hash_misses(void) {
    uint8_t hash[32];
    make_hash(hash, 0xCC);
    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(hash, &v) == false);
    (void)v;
    printf("  PASS: different hash returns miss\n");
}

static void test_invalidate_removes_entry(void) {
    uint8_t hash[32];
    make_hash(hash, 0xBB);
    dclaw_cache_invalidate(hash);

    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(hash, &v) == false);
    (void)v;
    printf("  PASS: invalidate removes entry\n");
}

static void test_untrusted_clock_cache_still_works(void) {
    /* The verdict cache now uses monotonic ticks (hal_tick_ms) for TTL
     * instead of wall-clock time. This means time_trusted no longer
     * affects cache behavior — entries are valid regardless of NTP sync
     * state. Verify that the cache still returns hits even when
     * time_trusted is false. */
    dclaw_state_t *s = dclaw_get_state();
    s->clock.time_trusted = false;

    uint8_t hash[32];
    make_hash(hash, 0xDD);
    dclaw_cache_store_with_ttl(hash, DCLAW_ACTION_BLOCK, DCLAW_SEV_HIGH, 60);

    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(hash, &v) == true);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.from_cache == true);
    (void)v;
    printf("  PASS: untrusted clock still returns cache hits (monotonic TTL)\n");

    s->clock.time_trusted = true;
}

static void test_flush_all_clears_cache(void) {
    uint8_t hash[32];
    make_hash(hash, 0xEE);
    dclaw_cache_store_with_ttl(hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO, 60);
    dclaw_cache_flush_all();

    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(hash, &v) == false);
    (void)v;
    printf("  PASS: flush_all clears all entries\n");
}

static void test_lru_eviction(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->clock.time_trusted = true;

    /* Fill all 64 cache slots */
    for (int i = 0; i < DCLAW_VERDICT_CACHE_SIZE; i++) {
        uint8_t hash[32];
        make_hash(hash, (uint8_t)i);
        dclaw_cache_store_with_ttl(hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO, 60);
    }

    /* Store one more — should evict LRU */
    uint8_t new_hash[32];
    make_hash(new_hash, 0xFF);
    dclaw_cache_store_with_ttl(new_hash, DCLAW_ACTION_BLOCK, DCLAW_SEV_HIGH, 60);

    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(new_hash, &v) == true);
    assert(v.action == DCLAW_ACTION_BLOCK);
    (void)v;
    printf("  PASS: LRU eviction works (new entry stored when full)\n");
}

static void test_duplicate_hashes_cannot_resurface(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint8_t hash[32];
    make_hash(hash, 0xA7);
    for (size_t i = 0; i < 2; i++) {
        memcpy(s->cache[i].tool_hash, hash, 32);
        s->cache[i].action = DCLAW_ACTION_ALLOW;
        s->cache[i].ttl_minutes = 60;
        s->cache[i].cached_at_tick = hal_tick_ms();
        s->cache[i].occupied = true;
    }
    dclaw_cache_invalidate(hash);
    dclaw_verdict_t verdict;
    assert(!dclaw_cache_lookup(hash, &verdict));
    assert(!s->cache[0].occupied && !s->cache[1].occupied);

    for (size_t i = 0; i < 2; i++) {
        memcpy(s->cache[i].tool_hash, hash, 32);
        s->cache[i].action = DCLAW_ACTION_ALLOW;
        s->cache[i].ttl_minutes = 60;
        s->cache[i].cached_at_tick = hal_tick_ms();
        s->cache[i].occupied = true;
    }
    dclaw_cache_store_with_ttl(hash, DCLAW_ACTION_BLOCK, DCLAW_SEV_HIGH, 2);
    size_t matching = 0;
    for (size_t i = 0; i < DCLAW_VERDICT_CACHE_SIZE; i++) {
        if (s->cache[i].occupied && memcmp(s->cache[i].tool_hash, hash, 32) == 0) matching++;
    }
    assert(matching == 1);
    assert(dclaw_cache_lookup(hash, &verdict));
    assert(verdict.action == DCLAW_ACTION_BLOCK && verdict.ttl_minutes == 2);
    dclaw_cache_store_with_ttl(hash, DCLAW_ACTION_BLOCK, DCLAW_SEV_HIGH, 0);
    assert(!dclaw_cache_lookup(hash, &verdict));
    printf("  PASS: revocation, replacement, and zero TTL clear duplicate prior ALLOWs\n");
}

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 1};
    dclaw_init(&info);

    printf("test_verdict_cache:\n");
    test_miss_on_empty();
    test_store_and_hit();
    test_different_hash_misses();
    test_invalidate_removes_entry();
    test_untrusted_clock_cache_still_works();
    test_flush_all_clears_cache();
    test_lru_eviction();
    test_duplicate_hashes_cannot_resurface();
    printf("  ALL PASSED (8 tests)\n");

    dclaw_shutdown();
    return 0;
}
#endif /* DCLAW_VERDICT_CACHE_SIZE > 0 */
