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

/* === Category-Specific Tests === */

static void test_detect_api_key_secret(void) {
    dclaw_scan_context_t ctx;
    const char *content = "Please use this API_KEY for authentication";
    int result = dclaw_content_scan(content, (uint16_t)strlen(content),
                                    DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result >= 1);
    assert(ctx.finding_count >= 1);
    assert(ctx.findings[0].category == DCLAW_CONTENT_CATEGORY_SECRET);
    assert(ctx.findings[0].severity == DCLAW_SEV_HIGH);
    printf("  PASS: detect API key secret\n");
}

static void test_detect_private_key_secret(void) {
    dclaw_scan_context_t ctx;
    const char *content = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...";
    int result = dclaw_content_scan(content, (uint16_t)strlen(content),
                                    DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result >= 1);
    assert(ctx.finding_count >= 1);
    assert(ctx.findings[0].category == DCLAW_CONTENT_CATEGORY_SECRET);
    printf("  PASS: detect private key secret\n");
}

static void test_detect_ssn_pii(void) {
    dclaw_scan_context_t ctx;
    const char *content = "My SSN is 123-45-6789 for verification";
    int result = dclaw_content_scan(content, (uint16_t)strlen(content),
                                    DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result >= 1);
    assert(ctx.finding_count >= 1);
    assert(ctx.findings[0].category == DCLAW_CONTENT_CATEGORY_PII);
    assert(ctx.findings[0].severity == DCLAW_SEV_CRITICAL);
    printf("  PASS: detect SSN PII\n");
}

static void test_detect_email_pii(void) {
    dclaw_scan_context_t ctx;
    const char *content = "Contact me at user@example.com for details";
    int result = dclaw_content_scan(content, (uint16_t)strlen(content),
                                    DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result >= 1);
    assert(ctx.finding_count >= 1);
    assert(ctx.findings[0].category == DCLAW_CONTENT_CATEGORY_PII);
    assert(ctx.findings[0].severity == DCLAW_SEV_MEDIUM);
    printf("  PASS: detect email PII\n");
}

static void test_detect_credit_card_pii(void) {
    dclaw_scan_context_t ctx;
    const char *content = "Card number: 4111111111111111 expires 12/25";
    int result = dclaw_content_scan(content, (uint16_t)strlen(content),
                                    DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result >= 1);
    assert(ctx.finding_count >= 1);
    assert(ctx.findings[0].category == DCLAW_CONTENT_CATEGORY_PII);
    assert(ctx.findings[0].severity == DCLAW_SEV_HIGH);
    printf("  PASS: detect credit card PII\n");
}

static void test_detect_username_credential(void) {
    dclaw_scan_context_t ctx;
    const char *content = "Please provide username: admin for access";
    int result = dclaw_content_scan(content, (uint16_t)strlen(content),
                                    DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result >= 1);
    assert(ctx.finding_count >= 1);
    assert(ctx.findings[0].category == DCLAW_CONTENT_CATEGORY_CREDENTIAL);
    assert(ctx.findings[0].severity == DCLAW_SEV_HIGH);
    printf("  PASS: detect username credential\n");
}

static void test_detect_bearer_token_credential(void) {
    dclaw_scan_context_t ctx;
    const char *content = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    int result = dclaw_content_scan(content, (uint16_t)strlen(content),
                                    DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result >= 1);
    assert(ctx.finding_count >= 1);
    assert(ctx.findings[0].category == DCLAW_CONTENT_CATEGORY_CREDENTIAL);
    printf("  PASS: detect bearer token credential\n");
}

static void test_detect_base64_exfil(void) {
    dclaw_scan_context_t ctx;
    /* 120+ character base64-like string */
    const char *content = "Data: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG9mIGEgbG9uZyBiYXNlNjQgZW5jb2RlZCBzdHJpbmcgdGhhdCBzaG91bGQgYmUgZGV0ZWN0ZWQgYXMgcG90ZW50aWFsIGV4ZmlsdHJhdGlvbiBkYXRh";
    int result = dclaw_content_scan(content, (uint16_t)strlen(content),
                                    DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result >= 1);
    assert(ctx.finding_count >= 1);
    assert(ctx.findings[0].category == DCLAW_CONTENT_CATEGORY_EXFIL);
    assert(ctx.findings[0].severity == DCLAW_SEV_MEDIUM);
    printf("  PASS: detect base64 exfil\n");
}

static void test_detect_sql_injection(void) {
    dclaw_scan_context_t ctx;
    const char *content = "Query: SELECT * FROM users WHERE id=1 OR 1=1";
    int result = dclaw_content_scan(content, (uint16_t)strlen(content),
                                    DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result >= 1);
    assert(ctx.finding_count >= 1);
    assert(ctx.findings[0].category == DCLAW_CONTENT_CATEGORY_INJECTION);
    assert(ctx.findings[0].severity == DCLAW_SEV_HIGH);
    printf("  PASS: detect SQL injection\n");
}

static void test_detect_xss_injection(void) {
    dclaw_scan_context_t ctx;
    const char *content = "Input: <script>alert('XSS')</script>";
    int result = dclaw_content_scan(content, (uint16_t)strlen(content),
                                    DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result >= 1);
    assert(ctx.finding_count >= 1);
    assert(ctx.findings[0].category == DCLAW_CONTENT_CATEGORY_INJECTION);
    printf("  PASS: detect XSS injection\n");
}

static void test_detect_path_traversal_injection(void) {
    dclaw_scan_context_t ctx;
    const char *content = "File path: ../../etc/shadow";
    int result = dclaw_content_scan(content, (uint16_t)strlen(content),
                                    DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result >= 1);
    assert(ctx.finding_count >= 1);
    assert(ctx.findings[0].category == DCLAW_CONTENT_CATEGORY_INJECTION);
    printf("  PASS: detect path traversal injection\n");
}

static void test_detect_shell_command(void) {
    dclaw_scan_context_t ctx;
    const char *content = "Execute: rm -rf /tmp/data";
    int result = dclaw_content_scan(content, (uint16_t)strlen(content),
                                    DCLAW_CONTENT_SCOPE_USER_INPUT, &ctx);
    assert(result >= 1);
    assert(ctx.finding_count >= 1);
    assert(ctx.findings[0].category == DCLAW_CONTENT_CATEGORY_COMMAND);
    assert(ctx.findings[0].severity == DCLAW_SEV_HIGH);
    printf("  PASS: detect shell command\n");
}

/* === SSRF Tests === */

static void test_ssrf_blocks_loopback(void) {
    assert(dclaw_ssrf_check_destination("127.0.0.1") == DCLAW_ACTION_BLOCK);
    assert(dclaw_ssrf_check_destination("localhost") == DCLAW_ACTION_BLOCK);
    printf("  PASS: SSRF blocks loopback\n");
}

static void test_ssrf_blocks_metadata(void) {
    assert(dclaw_ssrf_check_destination("169.254.169.254") == DCLAW_ACTION_BLOCK);
    printf("  PASS: SSRF blocks cloud metadata IP\n");
}

static void test_ssrf_blocks_rfc1918(void) {
    assert(dclaw_ssrf_check_destination("10.0.0.1") == DCLAW_ACTION_BLOCK);
    assert(dclaw_ssrf_check_destination("192.168.1.1") == DCLAW_ACTION_BLOCK);
    assert(dclaw_ssrf_check_destination("172.16.0.1") == DCLAW_ACTION_BLOCK);
    printf("  PASS: SSRF blocks RFC1918 private ranges\n");
}

static void test_ssrf_allows_public(void) {
    assert(dclaw_ssrf_check_destination("8.8.8.8") == DCLAW_ACTION_ALLOW);
    assert(dclaw_ssrf_check_destination("api.openai.com") == DCLAW_ACTION_ALLOW);
    printf("  PASS: SSRF allows public addresses\n");
}

static void test_ssrf_blocks_inline_credentials(void) {
    assert(dclaw_ssrf_check_destination("user:pass@api.example.com") == DCLAW_ACTION_BLOCK);
    printf("  PASS: SSRF blocks inline credentials\n");
}

/* === Worst Action Tests === */

static void test_high_severity_returns_block(void) {
    dclaw_scan_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.finding_count = 1;
    ctx.findings[0].category = DCLAW_CONTENT_CATEGORY_SECRET;
    ctx.findings[0].severity = DCLAW_SEV_HIGH;
    ctx.findings[0].offset = 0;

    dclaw_action_t action = dclaw_content_scan_worst_action(&ctx);
    assert(action == DCLAW_ACTION_BLOCK);
    printf("  PASS: HIGH severity returns BLOCK\n");
}

static void test_medium_severity_returns_warn(void) {
    dclaw_scan_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.finding_count = 1;
    ctx.findings[0].category = DCLAW_CONTENT_CATEGORY_PII;
    ctx.findings[0].severity = DCLAW_SEV_MEDIUM;
    ctx.findings[0].offset = 0;

    dclaw_action_t action = dclaw_content_scan_worst_action(&ctx);
    assert(action == DCLAW_ACTION_WARN);
    printf("  PASS: MEDIUM severity returns WARN\n");
}

int main(void) {
    printf("test_content_scanner:\n");

    /* Basic tests */
    test_empty_content_yields_zero_findings();
    test_null_content_yields_zero_findings();
    test_no_findings_returns_allow();

    /* Category-specific pattern detection tests */
    test_detect_api_key_secret();
    test_detect_private_key_secret();
    test_detect_ssn_pii();
    test_detect_email_pii();
    test_detect_credit_card_pii();
    test_detect_username_credential();
    test_detect_bearer_token_credential();
    test_detect_base64_exfil();
    test_detect_sql_injection();
    test_detect_xss_injection();
    test_detect_path_traversal_injection();
    test_detect_shell_command();

    /* SSRF tests */
    test_ssrf_blocks_loopback();
    test_ssrf_blocks_metadata();
    test_ssrf_blocks_rfc1918();
    test_ssrf_allows_public();
    test_ssrf_blocks_inline_credentials();

    /* Worst action tests */
    test_high_severity_returns_block();
    test_medium_severity_returns_warn();

    printf("  ALL PASSED (22 tests)\n");
    return 0;
}
