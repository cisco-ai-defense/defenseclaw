#include "content_scanner.h"
#include <string.h>

int dclaw_content_scan(const char *content, uint16_t content_len,
                       dclaw_content_scope_t scope,
                       dclaw_scan_context_t *ctx) {
    (void)scope; /* Unused in stub */

    if (!ctx) {
        return 0;
    }

    /* Initialize context */
    memset(ctx, 0, sizeof(*ctx));

    /* Stub: return 0 findings for NULL or empty content */
    if (!content || content_len == 0) {
        return 0;
    }

    /* Phase 1B stub: no actual pattern matching yet */
    return 0;
}

dclaw_action_t dclaw_content_scan_worst_action(const dclaw_scan_context_t *ctx) {
    if (!ctx || ctx->finding_count == 0) {
        return DCLAW_ACTION_ALLOW;
    }

    /* Check for HIGH or CRITICAL severity findings */
    for (uint8_t i = 0; i < ctx->finding_count; i++) {
        if (ctx->findings[i].severity >= DCLAW_SEV_HIGH) {
            return DCLAW_ACTION_BLOCK;
        }
    }

    /* Check for MEDIUM severity findings */
    for (uint8_t i = 0; i < ctx->finding_count; i++) {
        if (ctx->findings[i].severity >= DCLAW_SEV_MEDIUM) {
            return DCLAW_ACTION_WARN;
        }
    }

    return DCLAW_ACTION_ALLOW;
}

void dclaw_ssrf_init_tables(void) {
    /* Phase 1B stub: no DFA tables to initialize yet */
}

dclaw_action_t dclaw_ssrf_check_destination(const char *dest) {
    (void)dest; /* Unused in stub */
    /* Phase 1B stub: always allow */
    return DCLAW_ACTION_ALLOW;
}

dclaw_content_scope_t dclaw_infer_content_scope(dclaw_direction_t direction) {
    if (direction == DCLAW_DIRECTION_RESPONSE) {
        return DCLAW_CONTENT_SCOPE_TOOL_OUTPUT;
    }
    return DCLAW_CONTENT_SCOPE_USER_INPUT;
}
