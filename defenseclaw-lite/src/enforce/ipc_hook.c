#include "defenseclaw.h"
#include "platform.h"
#include <string.h>

#define IPC_SOCKET_PATH "/var/run/defenseclaw-lite.sock"

extern dclaw_state_t *dclaw_get_state(void);

static int ipc_server_fd = -1;
static uint32_t ipc_request_count_this_sec = 0;
static uint32_t ipc_last_rate_check_tick = 0;

static bool validate_ascii(const char *s, size_t max_len) {
    for (size_t i = 0; i < max_len && s[i] != '\0'; i++) {
        if (s[i] < 0x20 || s[i] > 0x7E) return false;
    }
    return true;
}

static bool validate_tool_hash(const uint8_t *hash) {
    /* Reject all-zeros (treated as "hash not provided") */
    uint8_t zero[32] = {0};
    return memcmp(hash, zero, 32) != 0;
}

int dclaw_ipc_verify_peer(int client_fd, dclaw_ipc_peer_t *peer) {
    uint32_t uid, gid;
    int32_t pid;

    if (hal_get_peer_cred(client_fd, &uid, &gid, &pid) != 0) return -1;
    if (uid != peer->expected_uid) return -1;
    if (gid != peer->expected_gid) return -1;

    /* Check PID start time to prevent recycle attacks */
    if (peer->registered_pid != 0) {
        uint64_t start = hal_get_pid_start_time(pid);
        if (start != peer->start_time) return -1;
    }

    return 0;
}

int dclaw_ipc_validate_request(const dclaw_tool_request_t *req) {
    /* REQ-15: ASCII validation on tool_name */
    if (!validate_ascii(req->tool_name, DCLAW_TOOL_NAME_MAX)) return -1;

    /* REQ-15: tool_hash must not be all zeros */
    if (!validate_tool_hash(req->tool_hash)) return -1;

    /* REQ-15: destination ASCII check (if non-empty) */
    if (req->destination[0] != '\0') {
        if (!validate_ascii(req->destination, DCLAW_DESTINATION_MAX)) return -1;
    }

    /* REQ-15: cap_flags must only have defined bits */
    if (req->cap_flags & 0x80) return -1;

    /* REQ-16: IPC rate limit */
    uint32_t now = hal_tick_ms();
    if (now - ipc_last_rate_check_tick >= 1000) {
        ipc_request_count_this_sec = 0;
        ipc_last_rate_check_tick = now;
    }
    ipc_request_count_this_sec++;
    if (ipc_request_count_this_sec > DCLAW_IPC_RATE_LIMIT_PER_SEC) return -1;

    return 0;
}

int dclaw_ipc_init(void) {
    ipc_server_fd = hal_ipc_socket_create(IPC_SOCKET_PATH);
    return (ipc_server_fd >= 0) ? 0 : -1;
}

void dclaw_ipc_shutdown(void) {
    if (ipc_server_fd >= 0) {
        hal_ipc_socket_close(ipc_server_fd);
        ipc_server_fd = -1;
    }
}
