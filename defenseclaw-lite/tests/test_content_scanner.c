#include "content_scanner.h"
#include "defenseclaw.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static void test_empty_content_yields_zero_findings(void) {
    dclaw_scan_context_t ctx;
    int result = dclaw_content_scan("", 0, DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result == 0);
    assert(ctx.finding_count == 0);
    printf("  PASS: empty content yields zero findings\n");
}

static void test_null_content_yields_zero_findings(void) {
    dclaw_scan_context_t ctx;
    int result = dclaw_content_scan(NULL, 100, DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result == 0);
    assert(ctx.finding_count == 0);
    printf("  PASS: NULL content yields zero findings\n");
}

static void test_no_findings_returns_allow(void) {
    dclaw_scan_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.finding_count = 0;

    dclaw_action_t action = dclaw_content_scan_worst_action(&ctx);
    assert(action == DCLAW_ACTION_ALLOW);
    printf("  PASS: no findings returns ALLOW\n");
}

int main(void) {
    printf("test_content_scanner:\n");
    test_empty_content_yields_zero_findings();
    test_null_content_yields_zero_findings();
    test_no_findings_returns_allow();
    printf("  ALL PASSED (3 tests)\n");
    return 0;
}
