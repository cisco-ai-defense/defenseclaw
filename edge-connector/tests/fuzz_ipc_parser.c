/*
 * AFL++ fuzz harness for IPC JSON-RPC parser.
 * Implements REQ-52: minimum 1M iterations.
 *
 * Build: afl-gcc -o fuzz_ipc fuzz_ipc_parser.c -I../include -I../build/include \
 *        -L../build -ldclaw_core
 * Run:   afl-fuzz -i corpus/ -o findings/ -- ./fuzz_ipc
 */

#include "defenseclaw.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

extern int dclaw_ipc_parse_request(const char *json, size_t json_len,
                                   dclaw_tool_request_t *out);
extern int dclaw_ipc_validate_request(const dclaw_tool_request_t *req);

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 1};
    dclaw_init(&info);

    /* Read fuzz input from stdin */
    char buf[1024];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
    if (n <= 0) return 0;
    buf[n] = '\0';

    /* Target 1: JSON parser (should never crash regardless of input) */
    dclaw_tool_request_t req;
    int rc = dclaw_ipc_parse_request(buf, (size_t)n, &req);

    /* Target 2: If parse succeeded, validate (should never crash) */
    if (rc == 0) {
        dclaw_ipc_validate_request(&req);
    }

    /* Target 3: If valid, evaluate (should never crash) */
    if (rc == 0 && dclaw_ipc_validate_request(&req) == 0) {
        dclaw_evaluate(&req);
    }

    dclaw_shutdown();
    return 0;
}
