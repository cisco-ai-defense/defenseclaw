#include "defenseclaw.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                             uint16_t target_hash, uint16_t session_id);
extern dclaw_state_t *dclaw_get_state(void);

static void test_block_flushes_immediately(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint32_t writes_before = s->audit_writer.total_flash_writes;

    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE, 0x1234, 1);

    assert(s->audit_writer.total_flash_writes > writes_before);
    assert(s->audit_writer.count == 0); /* buffer should be empty */
    printf("  PASS: BLOCK event flushes immediately\n");
}

static void test_warn_buffers(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint32_t writes_before = s->audit_writer.total_flash_writes;

    dclaw_audit_write(DCLAW_ACTION_WARN, DCLAW_REASON_CAP_SEQUENCE, 0x5678, 2);

    /* Should be buffered, not flushed yet */
    assert(s->audit_writer.count == 1);
    assert(s->audit_writer.total_flash_writes == writes_before);
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
    printf("  PASS: total_flash_writes counter incremented\n");
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
    printf("  ALL PASSED (4 tests)\n");

    dclaw_shutdown();
    return 0;
}
