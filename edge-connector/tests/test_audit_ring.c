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
#include <time.h>
#include "sha256.h"

extern int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                             uint32_t target_hash, uint16_t session_id);
extern dclaw_state_t *dclaw_get_state(void);
extern void dclaw_audit_tick(uint64_t now_ms);
extern bool dclaw_audit_sync_pending(void);
extern int dclaw_audit_sync_due_in_ms(uint64_t now_ms);

static void test_block_flushes_immediately(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint32_t writes_before = s->audit_writer.total_flash_writes;

    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE, 0x1234, 1);

    assert(s->audit_writer.total_flash_writes > writes_before);
    assert(s->audit_writer.count == 0); /* buffer should be empty */
    (void)writes_before;
    printf("  PASS: BLOCK event flushes immediately\n");
}

static void test_warn_buffers(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint32_t writes_before = s->audit_writer.total_flash_writes;

    dclaw_audit_write(DCLAW_ACTION_WARN, DCLAW_REASON_CAP_SEQUENCE, 0x5678, 2);

    /* Should be buffered, not flushed yet */
    assert(s->audit_writer.count == 1);
    assert(s->audit_writer.total_flash_writes == writes_before);
    (void)writes_before;
    printf("  PASS: WARN event buffered (not flushed)\n");
}

static void test_buffer_full_triggers_flush(void) {
    dclaw_state_t *s = dclaw_get_state();

    /* Fill remaining buffer slots */
    for (int i = s->audit_writer.count; i < DCLAW_AUDIT_RAM_BUFFER_SIZE; i++) {
        dclaw_audit_write(DCLAW_ACTION_ALLOW, DCLAW_REASON_POLICY_TABLE, (uint16_t)i, 1);
    }

    /* Buffer should have flushed */
    assert(s->audit_writer.count == 0);
    printf("  PASS: full buffer triggers flush\n");
}

static void test_flash_writes_tracked(void) {
    dclaw_state_t *s = dclaw_get_state();
    assert(s->audit_writer.total_flash_writes > 0);
    (void)s;
    printf("  PASS: total_flash_writes counter incremented\n");
}


static void sleep_ms(long ms) {
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static uint64_t flash_syncs(void) {
    hal_flash_stats_t st;
    hal_flash_get_stats(&st);
    return st.syncs;
}

/* Regression: every BLOCK (including IPC flood and junk rejections) cost
 * one fdatasync, or two when a buffered entry preceded it, so one peer
 * could drive thousands of syncs per second. */
static void test_block_flood_sync_rate_bounded(void) {
    dclaw_tool_request_t junk;
    memset(&junk, 0, sizeof(junk));
    strcpy(junk.tool_name, "no_such_tool");
    dclaw_sha256((const uint8_t *)junk.tool_name, strlen(junk.tool_name), junk.tool_hash);
    junk.session_id = 3;

    sleep_ms(DCLAW_AUDIT_BLOCK_SYNC_MS + 10);
    hal_flash_stats_t f0;
    hal_flash_get_stats(&f0);
    uint64_t t0 = hal_tick_ms();
    int n = 0;
    while (hal_tick_ms() - t0 < 500) { /* half a second of junk */
        /* A buffered (non-BLOCK) entry before each BLOCK forces a buffer
         * flush on every BLOCK; that flush is group-committed too. */
        if (n % 2) dclaw_audit_write(DCLAW_ACTION_ESCALATE, DCLAW_REASON_CLOUD_BLOCK, 0x77, 3);
        dclaw_verdict_t v = dclaw_evaluate(&junk);
        assert(v.action == DCLAW_ACTION_BLOCK);
        (void)v;
        n++;
    }
    uint64_t elapsed = hal_tick_ms() - t0;
    hal_flash_stats_t f1;
    hal_flash_get_stats(&f1);
    uint64_t syncs = f1.syncs - f0.syncs;
    double secs = elapsed > 0 ? elapsed / 1000.0 : 0.001;
    printf("    %d BLOCKs in %llu ms: %llu syncs (%.0f syncs/s, %.0f BLOCKs/s)\n",
           n, (unsigned long long)elapsed, (unsigned long long)syncs,
           syncs / secs, n / secs);
    /* Every entry still reaches flash at once... */
    assert(f1.writes - f0.writes >= (uint64_t)n);
    /* ...but at most one sync per window. */
    assert(syncs <= elapsed / DCLAW_AUDIT_BLOCK_SYNC_MS + 2);
    printf("  PASS: BLOCK flood syncs at most once per %d ms\n", DCLAW_AUDIT_BLOCK_SYNC_MS);
}

static void test_block_durable_within_window(void) {
    /* Inside a window: the BLOCK is written, its sync is pending. */
    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE, 0x1111, 4);
    uint64_t s0 = flash_syncs();
    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE, 0x2222, 4);
    assert(dclaw_audit_sync_pending());
    assert(flash_syncs() == s0);
    /* The window closes: the event loop tick syncs it. */
    sleep_ms(DCLAW_AUDIT_BLOCK_SYNC_MS + 10);
    dclaw_audit_tick(hal_tick_ms());
    assert(!dclaw_audit_sync_pending());
    assert(flash_syncs() == s0 + 1);
    /* After an idle window, a BLOCK is synced at once. */
    sleep_ms(DCLAW_AUDIT_BLOCK_SYNC_MS + 10);
    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE, 0x3333, 4);
    assert(!dclaw_audit_sync_pending());
    assert(flash_syncs() == s0 + 2);
    (void)s0;
    printf("  PASS: BLOCK entries are durable within one sync window\n");
}

static void test_failed_sync_stays_pending(void) {
    sleep_ms(DCLAW_AUDIT_BLOCK_SYNC_MS + 10);
    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE, 0x4444, 5);
    assert(!dclaw_audit_sync_pending());
    /* A BLOCK inside the window whose sync then fails stays pending... */
    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE, 0x5555, 5);
    assert(dclaw_audit_sync_pending());
    hal_flash_fail_next_syncs(1);
    sleep_ms(DCLAW_AUDIT_BLOCK_SYNC_MS + 10);
    dclaw_audit_tick(hal_tick_ms());
    assert(dclaw_audit_sync_pending());
    /* ...without making the loop spin: the retry waits for a new window. */
    assert(dclaw_audit_sync_due_in_ms(hal_tick_ms()) > 0);
    /* An explicit flush reports the failure. */
    hal_flash_fail_next_syncs(1);
    assert(dclaw_flush_audit() != 0);
    assert(dclaw_audit_sync_pending());
    /* The retry succeeds. */
    uint64_t s0 = flash_syncs();
    sleep_ms(DCLAW_AUDIT_BLOCK_SYNC_MS + 10);
    dclaw_audit_tick(hal_tick_ms());
    assert(!dclaw_audit_sync_pending());
    assert(flash_syncs() == s0 + 1);
    assert(dclaw_flush_audit() == 0);
    (void)s0;
    printf("  PASS: failed BLOCK sync stays pending and is reported\n");
}

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 1};
    dclaw_init(&info);

    printf("test_audit_ring:\n");
    test_block_flushes_immediately();
    test_warn_buffers();
    test_buffer_full_triggers_flush();
    test_flash_writes_tracked();
    test_block_flood_sync_rate_bounded();
    test_block_durable_within_window();
    test_failed_sync_stays_pending();
    printf("  ALL PASSED (6 tests)\n");

    dclaw_shutdown();
    return 0;
}
