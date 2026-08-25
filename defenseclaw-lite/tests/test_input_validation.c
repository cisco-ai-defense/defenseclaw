#include "defenseclaw.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern int dclaw_ipc_validate_request(const dclaw_tool_request_t *req);
extern int dclaw_ipc_parse_request(const char *json, size_t json_len,
                                   dclaw_tool_request_t *out);

static dclaw_tool_request_t make_valid_request(void) {
    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.tool_name, "bash", DCLAW_TOOL_NAME_MAX - 1);
    memset(req.tool_hash, 0xAB, 32);
    req.cap_flags = DCLAW_CAP_EXEC_SHELL;
    req.session_id = 1;
    return req;
}

static void test_valid_request_passes(void) {
    dclaw_tool_request_t req = make_valid_request();
    assert(dclaw_ipc_validate_request(&req) == 0);
    printf("  PASS: valid request accepted\n");
}

static void test_non_ascii_tool_name_rejected(void) {
    dclaw_tool_request_t req = make_valid_request();
    req.tool_name[2] = (char)0x80;
    assert(dclaw_ipc_validate_request(&req) == -1);
    printf("  PASS: non-ASCII tool_name rejected\n");
}

static void test_control_char_tool_name_rejected(void) {
    dclaw_tool_request_t req = make_valid_request();
    req.tool_name[0] = 0x01; /* SOH control char */
    assert(dclaw_ipc_validate_request(&req) == -1);
    printf("  PASS: control char in tool_name rejected\n");
}

static void test_all_zero_hash_rejected(void) {
    dclaw_tool_request_t req = make_valid_request();
    memset(req.tool_hash, 0, 32);
    assert(dclaw_ipc_validate_request(&req) == -1);
    printf("  PASS: all-zero hash rejected\n");
}

static void test_invalid_cap_flags_rejected(void) {
    dclaw_tool_request_t req = make_valid_request();
    req.cap_flags = 0x80;
    assert(dclaw_ipc_validate_request(&req) == -1);
    printf("  PASS: invalid cap_flags (0x80) rejected\n");
}

static void test_valid_cap_flags_accepted(void) {
    dclaw_tool_request_t req = make_valid_request();
    req.cap_flags = 0x7F; /* all valid bits set */
    assert(dclaw_ipc_validate_request(&req) == 0);
    printf("  PASS: all valid cap_flags (0x7F) accepted\n");
}

static void test_non_ascii_destination_rejected(void) {
    dclaw_tool_request_t req = make_valid_request();
    strncpy(req.destination, "evil.com", DCLAW_DESTINATION_MAX - 1);
    req.destination[4] = (char)0xFF;
    assert(dclaw_ipc_validate_request(&req) == -1);
    printf("  PASS: non-ASCII destination rejected\n");
}

static void test_empty_destination_accepted(void) {
    dclaw_tool_request_t req = make_valid_request();
    req.destination[0] = '\0';
    assert(dclaw_ipc_validate_request(&req) == 0);
    printf("  PASS: empty destination accepted\n");
}

static void test_json_parse_valid(void) {
    const char *json =
        "{\"jsonrpc\":\"2.0\",\"method\":\"evaluate\",\"params\":{"
        "\"tool_name\":\"bash\","
        "\"tool_hash\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\","
        "\"capabilities\":4,"
        "\"session_id\":1,"
        "\"destination\":\"api.openai.com\""
        "},\"id\":1}";
    dclaw_tool_request_t out;
    int rc = dclaw_ipc_parse_request(json, strlen(json), &out);
    assert(rc == 0);
    assert(strcmp(out.tool_name, "bash") == 0);
    assert(out.cap_flags == 4);
    assert(out.session_id == 1);
    assert(strcmp(out.destination, "api.openai.com") == 0);
    assert(out.tool_hash[0] == 0xab);
    assert(out.tool_hash[1] == 0xcd);
    printf("  PASS: valid JSON-RPC parsed correctly\n");
}

static void test_json_parse_missing_field(void) {
    const char *json =
        "{\"jsonrpc\":\"2.0\",\"method\":\"evaluate\",\"params\":{"
        "\"tool_name\":\"bash\","
        "\"capabilities\":4,"
        "\"session_id\":1"
        "},\"id\":1}";
    dclaw_tool_request_t out;
    assert(dclaw_ipc_parse_request(json, strlen(json), &out) == -1);
    printf("  PASS: missing tool_hash field rejected\n");
}

static void test_json_parse_bad_hash_length(void) {
    const char *json =
        "{\"jsonrpc\":\"2.0\",\"method\":\"evaluate\",\"params\":{"
        "\"tool_name\":\"test\","
        "\"tool_hash\":\"abcdef\","
        "\"capabilities\":1,"
        "\"session_id\":1"
        "},\"id\":1}";
    dclaw_tool_request_t out;
    assert(dclaw_ipc_parse_request(json, strlen(json), &out) == -1);
    printf("  PASS: short tool_hash string rejected\n");
}

static void test_json_parse_oversized_rejected(void) {
    char big[600];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    dclaw_tool_request_t out;
    assert(dclaw_ipc_parse_request(big, sizeof(big) - 1, &out) == -1);
    printf("  PASS: oversized payload (>512B) rejected\n");
}

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 1};
    dclaw_init(&info);

    printf("test_input_validation:\n");
    test_valid_request_passes();
    test_non_ascii_tool_name_rejected();
    test_control_char_tool_name_rejected();
    test_all_zero_hash_rejected();
    test_invalid_cap_flags_rejected();
    test_valid_cap_flags_accepted();
    test_non_ascii_destination_rejected();
    test_empty_destination_accepted();
    test_json_parse_valid();
    test_json_parse_missing_field();
    test_json_parse_bad_hash_length();
    test_json_parse_oversized_rejected();
    printf("  ALL PASSED (12 tests)\n");

    dclaw_shutdown();
    return 0;
}
