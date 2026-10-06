/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unit tests for the Muse Gadget SDK bridge.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../src/muse/muse_bridge.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define RUN(name) do { \
    printf("  %-50s", #name); \
    name(); \
    printf("PASS\n"); \
    tests_passed++; \
} while (0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAIL (line %d: %u != %u)\n", __LINE__, (unsigned)(a), (unsigned)(b)); \
        tests_failed++; \
        return; \
    } \
} while (0)

#define ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("FAIL (line %d: \"%s\" != \"%s\")\n", __LINE__, (a), (b)); \
        tests_failed++; \
        return; \
    } \
} while (0)

TEST(test_command_to_caps_system_run) {
    ASSERT_EQ(muse_command_to_caps("system.run"), DCLAW_CAP_EXEC_SHELL);
}

TEST(test_command_to_caps_file_read) {
    ASSERT_EQ(muse_command_to_caps("file.read"), DCLAW_CAP_READ_FS);
}

TEST(test_command_to_caps_file_write) {
    ASSERT_EQ(muse_command_to_caps("file.write"), DCLAW_CAP_WRITE_FS);
}

TEST(test_command_to_caps_device_health) {
    ASSERT_EQ(muse_command_to_caps("device.health"), DCLAW_CAP_SENSOR_READ);
}

TEST(test_command_to_caps_unknown) {
    ASSERT_EQ(muse_command_to_caps("unknown.command"), DCLAW_CAP_UNKNOWN);
}

TEST(test_command_to_caps_empty) {
    ASSERT_EQ(muse_command_to_caps(""), DCLAW_CAP_UNKNOWN);
}

TEST(test_command_to_caps_null) {
    ASSERT_EQ(muse_command_to_caps(NULL), DCLAW_CAP_UNKNOWN);
}

TEST(test_build_request_system_run) {
    dclaw_tool_request_t req;
    uint8_t hash[32];
    memset(hash, 0xAA, sizeof(hash));

    int rc = muse_build_request(&req, "system.run", hash, 42, "ls -la", 6);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(req.tool_name, "system.run");
    ASSERT_EQ(req.cap_flags, DCLAW_CAP_EXEC_SHELL);
    ASSERT_EQ(req.session_id, 42);
    ASSERT_EQ(req.direction, DCLAW_DIRECTION_REQUEST);
    ASSERT_EQ(req.content_scope, DCLAW_CONTENT_SCOPE_USER_INPUT);
    ASSERT_EQ(req.content_len, 6);
    ASSERT_STR_EQ(req.content_buf, "ls -la");
    ASSERT_EQ(req.tool_hash[0], 0xAA);
}

TEST(test_build_request_file_read) {
    dclaw_tool_request_t req;
    uint8_t hash[32];
    memset(hash, 0xBB, sizeof(hash));

    int rc = muse_build_request(&req, "file.read", hash, 1, NULL, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(req.tool_name, "file.read");
    ASSERT_EQ(req.cap_flags, DCLAW_CAP_READ_FS);
    ASSERT_EQ(req.content_len, 0);
}

TEST(test_build_request_file_write) {
    dclaw_tool_request_t req;
    uint8_t hash[32];
    memset(hash, 0xCC, sizeof(hash));

    int rc = muse_build_request(&req, "file.write", hash, 10, "/tmp/test", 9);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(req.tool_name, "file.write");
    ASSERT_EQ(req.cap_flags, DCLAW_CAP_WRITE_FS);
    ASSERT_EQ(req.content_len, 9);
}

TEST(test_build_request_unknown_command) {
    dclaw_tool_request_t req;
    uint8_t hash[32];
    memset(hash, 0, sizeof(hash));

    int rc = muse_build_request(&req, "unknown.cmd", hash, 1, NULL, 0);
    ASSERT_EQ(rc, -1);
}

TEST(test_build_request_device_health) {
    dclaw_tool_request_t req;
    uint8_t hash[32];
    memset(hash, 0xDD, sizeof(hash));

    int rc = muse_build_request(&req, "device.health", hash, 5, NULL, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(req.tool_name, "device.health");
    ASSERT_EQ(req.cap_flags, DCLAW_CAP_SENSOR_READ);
}

TEST(test_build_request_content_truncation) {
    dclaw_tool_request_t req;
    uint8_t hash[32];
    memset(hash, 0, sizeof(hash));

    char long_content[2048];
    memset(long_content, 'A', sizeof(long_content));
    long_content[sizeof(long_content) - 1] = '\0';

    int rc = muse_build_request(&req, "system.run", hash, 1,
                                 long_content, sizeof(long_content) - 1);
    ASSERT_EQ(rc, 0);
    assert(req.content_len < sizeof(long_content));
}

TEST(test_build_request_null_req) {
    uint8_t hash[32];
    memset(hash, 0, sizeof(hash));
    int rc = muse_build_request(NULL, "system.run", hash, 1, NULL, 0);
    ASSERT_EQ(rc, -1);
}

TEST(test_build_request_null_command) {
    dclaw_tool_request_t req;
    uint8_t hash[32];
    memset(hash, 0, sizeof(hash));
    int rc = muse_build_request(&req, NULL, hash, 1, NULL, 0);
    ASSERT_EQ(rc, -1);
}

int main(void) {
    printf("Muse bridge tests:\n");
    RUN(test_command_to_caps_system_run);
    RUN(test_command_to_caps_file_read);
    RUN(test_command_to_caps_file_write);
    RUN(test_command_to_caps_device_health);
    RUN(test_command_to_caps_unknown);
    RUN(test_command_to_caps_empty);
    RUN(test_command_to_caps_null);
    RUN(test_build_request_system_run);
    RUN(test_build_request_file_read);
    RUN(test_build_request_file_write);
    RUN(test_build_request_unknown_command);
    RUN(test_build_request_device_health);
    RUN(test_build_request_content_truncation);
    RUN(test_build_request_null_req);
    RUN(test_build_request_null_command);

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
