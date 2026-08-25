#include "defenseclaw.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern bool dclaw_cache_lookup(const uint8_t *tool_hash, dclaw_verdict_t *out);
extern void dclaw_cache_store(const uint8_t *tool_hash, dclaw_action_t action,
                              dclaw_severity_t severity);
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
    printf("  PASS: lookup on empty cache returns miss\n");
}

static void test_store_and_hit(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->clock.time_trusted = true;

    uint8_t hash[32];
    make_hash(hash, 0xBB);
    dclaw_cache_store(hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO);

    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(hash, &v) == true);
    assert(v.action == DCLAW_ACTION_ALLOW);
    assert(v.from_cache == true);
    printf("  PASS: store + lookup returns cached verdict\n");
}

static void test_different_hash_misses(void) {
    uint8_t hash[32];
    make_hash(hash, 0xCC);
    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(hash, &v) == false);
    printf("  PASS: different hash returns miss\n");
}

static void test_invalidate_removes_entry(void) {
    uint8_t hash[32];
    make_hash(hash, 0xBB);
    dclaw_cache_invalidate(hash);

    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(hash, &v) == false);
    printf("  PASS: invalidate removes entry\n");
}

static void test_untrusted_clock_always_misses(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->clock.time_trusted = false;

    uint8_t hash[32];
    make_hash(hash, 0xDD);
    dclaw_cache_store(hash, DCLAW_ACTION_BLOCK, DCLAW_SEV_HIGH);

    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(hash, &v) == false);
    printf("  PASS: untrusted clock treats all entries as expired\n");

    s->clock.time_trusted = true;
}

static void test_flush_all_clears_cache(void) {
    uint8_t hash[32];
    make_hash(hash, 0xEE);
    dclaw_cache_store(hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO);
    dclaw_cache_flush_all();

    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(hash, &v) == false);
    printf("  PASS: flush_all clears all entries\n");
}

static void test_lru_eviction(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->clock.time_trusted = true;

    /* Fill all 64 cache slots */
    for (int i = 0; i < DCLAW_VERDICT_CACHE_SIZE; i++) {
        uint8_t hash[32];
        make_hash(hash, (uint8_t)i);
        dclaw_cache_store(hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO);
    }

    /* Store one more — should evict LRU */
    uint8_t new_hash[32];
    make_hash(new_hash, 0xFF);
    dclaw_cache_store(new_hash, DCLAW_ACTION_BLOCK, DCLAW_SEV_HIGH);

    dclaw_verdict_t v;
    assert(dclaw_cache_lookup(new_hash, &v) == true);
    assert(v.action == DCLAW_ACTION_BLOCK);
    printf("  PASS: LRU eviction works (new entry stored when full)\n");
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
    test_untrusted_clock_always_misses();
    test_flush_all_clears_cache();
    test_lru_eviction();
    printf("  ALL PASSED (7 tests)\n");

    dclaw_shutdown();
    return 0;
}
