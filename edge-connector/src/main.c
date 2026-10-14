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
#include "config.h"
#include "hmac_sha256.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#ifndef DCLAW_IPC_SOCKET_PATH_DEFAULT
#define DCLAW_IPC_SOCKET_PATH_DEFAULT "/run/defenseclaw/defenseclaw.sock"
#endif

#define DCLAW_MAX_IPC_CLIENTS 8
#define DCLAW_IPC_BUF_SIZE    (DCLAW_IPC_MAX_PAYLOAD + 1)

/* External module functions */
#if DCLAW_MQTT_ENABLED
extern int  dclaw_mqtt_init(void);
extern int  dclaw_mqtt_connect(void);
extern int  dclaw_mqtt_send_heartbeat(void);
extern int  dclaw_mqtt_reconnect(void);
extern int  dclaw_mqtt_poll(int timeout_ms);
extern void dclaw_canary_tick(void);
#endif
extern int  dclaw_ipc_parse_request(const char *json, size_t json_len,
                                    dclaw_tool_request_t *out);
extern int  dclaw_ipc_verify_peer(int client_fd, dclaw_ipc_peer_t *peer);
extern dclaw_state_t *dclaw_get_state(void);
#if DCLAW_MQTT_ENABLED
extern int  dclaw_ipc_release_lockdown(void);
extern void dclaw_lockdown_timeout_check(void);
#endif

static volatile sig_atomic_t g_running = 1;

/* Local lockdown timeout: auto-release block_all after this many seconds.
 * This is a faster local safety net (1 hour) in addition to the 24-hour
 * timeout in ota_receiver.c, and works even when MQTT is disabled. */
#if !DCLAW_MQTT_ENABLED
static uint64_t block_all_activated_tick = 0;
#define DCLAW_LOCKDOWN_TIMEOUT_SECS 3600
#endif

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static uint32_t safe_strtoul(const char *s, uint32_t max_val, uint32_t default_val) {
    if (!s || !s[0]) return default_val;
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno == ERANGE || v > max_val || *end != '\0') {
        fprintf(stderr, "[DCLAW] WARNING: Invalid numeric env var value '%s', using default %u\n",
                s, default_val);
        return default_val;
    }
    return (uint32_t)v;
}

/* Static action string lookup table.  Index must match dclaw_action_t values.
 * All strings are JSON-safe literals (no quotes, backslashes, or control chars). */
static const char *const action_strings[] = {
    [DCLAW_ACTION_ALLOW]    = "allow",
    [DCLAW_ACTION_BLOCK]    = "block",
    [DCLAW_ACTION_WARN]     = "warn",
    [DCLAW_ACTION_ESCALATE] = "escalate",
};
#define ACTION_STRINGS_COUNT (sizeof(action_strings) / sizeof(action_strings[0]))

static const char *action_string(dclaw_action_t a) {
    if ((unsigned)a < ACTION_STRINGS_COUNT && action_strings[(unsigned)a] != NULL)
        return action_strings[(unsigned)a];
    return "unknown";
}

/* Write a JSON-RPC response for a verdict back to the client fd.
 * Loops on partial writes to ensure the full response is sent.
 * Returns 0 on success, -1 on write failure. */
static int write_verdict_response(int fd, const dclaw_verdict_t *v, int32_t request_id) {
    /* Validate action is within the known range before formatting into JSON.
     * Out-of-range values are clamped to "unknown" by action_string(). */
    const char *action_str = action_string(v->action);

    char resp[256];
    int n = snprintf(resp, sizeof(resp),
        "{\"jsonrpc\":\"2.0\",\"result\":{\"action\":\"%s\","
        "\"reason\":%u,\"severity\":%u,\"from_cache\":%s},\"id\":%d}\n",
        action_str,
        (unsigned)v->reason,
        (unsigned)v->severity,
        v->from_cache ? "true" : "false",
        (int)request_id);
    if (n <= 0 || (size_t)n >= sizeof(resp)) return -1;

    size_t total = (size_t)n;
    size_t written = 0;
    while (written < total) {
        ssize_t w = write(fd, resp + written, total - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        written += (size_t)w;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    /* Parse --help / --version before any initialization */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            fprintf(stdout,
                "Usage: edge-connector [OPTIONS]\n"
                "DefenseClaw edge-connector daemon " DCLAW_VERSION "\n\n"
                "Options:\n"
                "  -h, --help       Show this help and exit\n"
                "  -V, --version    Show version and exit\n\n"
                "Environment variables:\n"
                "  DCLAW_IPC_SOCKET_PATH  IPC socket path (default: /run/defenseclaw/defenseclaw.sock)\n"
                "  DCLAW_FLASH_PATH       Flash backing file path\n"
                "  DCLAW_AUDIT_KEY        Audit HMAC key (hex)\n"
                "  DCLAW_DEVICE_KEY       Device HMAC key (hex)\n"
                "  DCLAW_LOG_LEVEL        Log level: 0=error, 1=warn, 2=info, 3=debug\n"
                "\nWARNING: DCLAW_FAIL_OPEN=1 disables enforcement when backend is unavailable.\n"
                "         Use only for debugging. Never in production.\n");
            return 0;
        }
        if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-V") == 0) {
            fprintf(stdout, "edge-connector %s\n", DCLAW_VERSION);
            return 0;
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    signal(SIGPIPE, SIG_IGN);

    const char *env_tenant = getenv("DCLAW_TENANT_ID");
    const char *env_fleet  = getenv("DCLAW_FLEET_ID");
    const char *env_device = getenv("DCLAW_DEVICE_ID");

    dclaw_device_info_t info = {
        .tenant_id = (uint16_t)safe_strtoul(env_tenant, 65535, 1),
        .fleet_id  = (uint16_t)safe_strtoul(env_fleet,  65535, 1),
        .device_id = safe_strtoul(env_device, UINT32_MAX, 0),
        .policy_version = 0,
        .fw_version = 1,
        .hw_profile = 2, /* LINUX_SBC */
        .capabilities = 0xFF,
    };

    if (dclaw_init(&info) != 0) {
        fprintf(stderr, "edge-connector: init failed\n");
        return 1;
    }

#ifdef __linux__
    /* Prevent /proc/PID/environ access by other same-UID processes since
     * dclaw_scrub_env() cannot clear the snapshot taken at exec time. */
    prctl(PR_SET_DUMPABLE, 0);
#endif

    /* Set IPC peer expected UID/GID so non-root users can connect.
     * By default, accept connections from the same user that started the
     * daemon.  Env vars DCLAW_IPC_ALLOWED_UID / DCLAW_IPC_ALLOWED_GID
     * override this for multi-user setups (e.g., daemon runs as root but
     * CLI runs as a service account). */
    {
        dclaw_state_t *st = dclaw_get_state();
        const char *env_uid = getenv("DCLAW_IPC_ALLOWED_UID");
        const char *env_gid = getenv("DCLAW_IPC_ALLOWED_GID");
        st->ipc_peer.expected_uid = safe_strtoul(env_uid, UINT32_MAX, (uint32_t)getuid());
        st->ipc_peer.expected_gid = safe_strtoul(env_gid, UINT32_MAX, (uint32_t)getgid());
    }

    /* Resolve IPC socket path: env var override, then compile-time default */
    const char *env_ipc = getenv("DCLAW_IPC_SOCKET_PATH");
    const char *ipc_socket_path = (env_ipc && env_ipc[0] != '\0')
                                  ? env_ipc : DCLAW_IPC_SOCKET_PATH_DEFAULT;

    /* Validate IPC socket path: reject path traversal and overly long paths */
    if (ipc_socket_path) {
        if (strstr(ipc_socket_path, "..") != NULL) {
            fprintf(stderr, "[DCLAW] ERROR: IPC socket path must not contain '..'\n");
            return 1;
        }
        if (strlen(ipc_socket_path) > 104) {
            fprintf(stderr, "[DCLAW] ERROR: IPC socket path too long (max 104)\n");
            return 1;
        }
#if !DCLAW_DEV_MODE
        if (strncmp(ipc_socket_path, "/run/", 5) != 0 && strncmp(ipc_socket_path, "/var/", 5) != 0) {
            fprintf(stderr, "[DCLAW] ERROR: IPC socket path must be under /run/ or /var/ in production\n");
            return 1;
        }
#endif
    }

    /* Initialize MQTT and attempt initial connection */
#if DCLAW_MQTT_ENABLED
    (void)dclaw_mqtt_init();
    (void)dclaw_mqtt_connect();
#endif

    /* Create the IPC Unix domain socket */
    int server_fd = hal_ipc_socket_create(ipc_socket_path);
    if (server_fd < 0) {
        fprintf(stderr, "edge-connector: failed to create IPC socket at %s\n",
                ipc_socket_path);
        dclaw_shutdown();
        return 1;
    }

    fprintf(stderr, "edge-connector: running (profile=%s, ipc=%s)\n",
            DCLAW_PROFILE_NAME, ipc_socket_path);

    /* pollfd array: slot 0 = server socket, slots 1..MAX = client connections */
    struct pollfd fds[1 + DCLAW_MAX_IPC_CLIENTS];
    int client_fds[DCLAW_MAX_IPC_CLIENTS];
    int num_clients = 0;

    /* Per-client accumulation buffers for newline-delimited message framing */
    static char   client_buf[DCLAW_MAX_IPC_CLIENTS][DCLAW_IPC_BUF_SIZE];
    static size_t client_buf_len[DCLAW_MAX_IPC_CLIENTS];

    memset(fds, 0, sizeof(fds));
    memset(client_buf_len, 0, sizeof(client_buf_len));
    for (int i = 0; i < DCLAW_MAX_IPC_CLIENTS; i++)
        client_fds[i] = -1;

    fds[0].fd = server_fd;
    fds[0].events = POLLIN;

    uint64_t last_idle_flush = hal_tick_ms();

    while (g_running) {
        hal_watchdog_feed();

        /* Build the pollfd set: server + active clients */
        int nfds = 1;
        for (int i = 0; i < num_clients; i++) {
            fds[nfds].fd = client_fds[i];
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }

        int ready = poll(fds, (nfds_t)nfds, 10 /* 10ms timeout */);

        /* Accept new connections */
        if (ready > 0 && (fds[0].revents & POLLIN)) {
            int client_fd = hal_ipc_socket_accept(server_fd);
            if (client_fd >= 0) {
                /* Verify peer credentials before admitting the connection */
                if (dclaw_ipc_verify_peer(client_fd, &dclaw_get_state()->ipc_peer) != 0) {
                    hal_ipc_socket_close(client_fd);
                } else if (num_clients < DCLAW_MAX_IPC_CLIENTS) {
                    client_fds[num_clients] = client_fd;
                    num_clients++;
                } else {
                    /* At capacity, reject */
                    hal_ipc_socket_close(client_fd);
                }
            }
        }

        /* Process data from connected clients */
        for (int i = 0; i < num_clients; i++) {
            int slot = 1 + i; /* pollfd index */
            if (slot >= nfds) break;
            if (!(fds[slot].revents & POLLIN)) continue;

            /* Read into the per-client accumulation buffer */
            size_t space = DCLAW_IPC_BUF_SIZE - 1 - client_buf_len[i];
            if (space == 0) {
                /* Buffer full with no newline — discard and reset */
                client_buf_len[i] = 0;
                space = DCLAW_IPC_BUF_SIZE - 1;
            }
            ssize_t n = read(client_fds[i], client_buf[i] + client_buf_len[i], space);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                /* Non-blocking: no data yet, skip this client */
                continue;
            }
            if (n <= 0) {
                /* Client disconnected or error. Swap-remove and do NOT
                 * re-check slot i: the swapped-in client's fds[] entry is
                 * stale (built before poll). It will be polled next cycle. */
                hal_ipc_socket_close(client_fds[i]);
                num_clients--;
                if (i < num_clients) {
                    client_fds[i] = client_fds[num_clients];
                    client_buf_len[i] = client_buf_len[num_clients];
                    memcpy(client_buf[i], client_buf[num_clients], client_buf_len[i]);
                }
                client_fds[num_clients] = -1;
                client_buf_len[num_clients] = 0;
                continue;
            }
            client_buf_len[i] += (size_t)n;

            /* Process complete newline-delimited messages */
            char *base = client_buf[i];
            size_t remaining = client_buf_len[i];
            char *nl;
            while ((nl = memchr(base, '\n', remaining)) != NULL) {
                size_t msg_len = (size_t)(nl - base);
                *nl = '\0';

#if DCLAW_MQTT_ENABLED
                if (msg_len >= 16 && memcmp(base, "release_lockdown", 16) == 0) {
                    extern uint32_t dclaw_load_lockdown_release_seq(void);
                    extern void dclaw_store_lockdown_release_seq(uint32_t);
                    static uint32_t lockdown_release_seq = 0;
                    static bool release_seq_loaded = false;
                    if (!release_seq_loaded) {
                        lockdown_release_seq = dclaw_load_lockdown_release_seq();
                        release_seq_loaded = true;
                    }
                    bool authenticated = false;
                    if (msg_len == 16) {
#if DCLAW_DEV_MODE
                        authenticated = true;
#else
                        const char *deny = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000,\"message\":\"HMAC required for lockdown release in production\"},\"id\":null}\n";
                        if (write(client_fds[i], deny, strlen(deny)) < 0) { /* best-effort */ }
#endif
                    } else if (msg_len > 17 && base[16] == ':') {
                        char *colon2 = memchr(base + 17, ':', msg_len - 17);
                        if (colon2 != NULL) {
                            size_t seq_len = (size_t)(colon2 - (base + 17));
                            size_t hmac_hex_len = msg_len - 17 - seq_len - 1;
                            if (seq_len > 0 && seq_len <= 8 && hmac_hex_len == 64) {
                                uint32_t req_seq = 0;
                                bool seq_ok = true;
                                for (size_t si = 0; si < seq_len; si++) {
                                    char ch = base[17 + si];
                                    if (ch < '0' || ch > '9') { seq_ok = false; break; }
                                    uint32_t prev = req_seq;
                                    req_seq = req_seq * 10 + (uint32_t)(ch - '0');
                                    if (req_seq < prev) { seq_ok = false; break; }
                                }
                                if (seq_ok && req_seq > lockdown_release_seq) {
                                    uint8_t provided[32];
                                    bool hex_ok = (dclaw_hex_decode(colon2 + 1, provided, 32) == 0);
                                    if (hex_ok) {
                                        extern const uint8_t *dclaw_emergency_get_key(size_t *out_len);
                                        size_t key_len = 0;
                                        const uint8_t *ekey = dclaw_emergency_get_key(&key_len);
                                        if (ekey && key_len == 32) {
                                            size_t prefix_len = (size_t)(colon2 - base);
                                            uint8_t expected[32];
                                            dclaw_hmac_sha256(ekey, key_len,
                                                (const uint8_t *)base, prefix_len, expected);
                                            authenticated = ct_compare(provided, expected, 32);
                                            if (authenticated) {
                                                lockdown_release_seq = req_seq;
                                                dclaw_store_lockdown_release_seq(req_seq);
                                            } else {
                                                fprintf(stderr, "[DCLAW] WARNING: IPC lockdown release HMAC mismatch\n");
                                            }
                                        }
                                    }
                                } else if (seq_ok) {
                                    fprintf(stderr, "[DCLAW] WARNING: IPC lockdown release replay rejected (seq=%u, last=%u)\n",
                                            req_seq, lockdown_release_seq);
                                }
                            }
                        } else if (msg_len == 81) {
                            uint8_t provided[32];
                            bool hex_ok = (dclaw_hex_decode(base + 17, provided, 32) == 0);
                            if (hex_ok) {
                                extern const uint8_t *dclaw_emergency_get_key(size_t *out_len);
                                size_t key_len = 0;
                                const uint8_t *ekey = dclaw_emergency_get_key(&key_len);
                                if (ekey && key_len == 32) {
                                    uint8_t expected[32];
                                    dclaw_hmac_sha256(ekey, key_len,
                                        (const uint8_t *)"release_lockdown", 16, expected);
                                    authenticated = ct_compare(provided, expected, 32);
                                    if (!authenticated) {
                                        fprintf(stderr, "[DCLAW] WARNING: IPC lockdown release HMAC mismatch\n");
                                    }
                                }
                            }
                        }
                    }
                    if (authenticated) {
                        int rc = dclaw_ipc_release_lockdown();
                        const char *ok_resp = "{\"jsonrpc\":\"2.0\",\"result\":{\"released\":true},\"id\":null}\n";
                        const char *no_resp = "{\"jsonrpc\":\"2.0\",\"result\":{\"released\":false,\"reason\":\"not in lockdown\"},\"id\":null}\n";
                        const char *resp = (rc == 0) ? ok_resp : no_resp;
                        if (write(client_fds[i], resp, strlen(resp)) < 0) { /* best-effort */ }
                    }
                } else
#endif
                /* Parse JSON-RPC request and evaluate */
                {
                dclaw_tool_request_t req;
                if (msg_len > 0 && dclaw_ipc_parse_request(base, msg_len, &req) == 0) {
                    dclaw_verdict_t verdict = dclaw_evaluate(&req);
                    (void)write_verdict_response(client_fds[i], &verdict, req.request_id);
                } else if (msg_len > 0) {
                    /* Malformed request — send error response */
                    const char *err =
                        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,"
                        "\"message\":\"Invalid Request\"},\"id\":null}\n";
                    if (write(client_fds[i], err, strlen(err)) < 0) {
                        /* Best-effort error response — ignore write failure */
                    }
                }
                }

                size_t consumed = msg_len + 1;
                base += consumed;
                remaining -= consumed;
            }

            /* Shift any remaining partial message to the front of the buffer */
            if (remaining > 0 && base != client_buf[i]) {
                memmove(client_buf[i], base, remaining);
            }
            client_buf_len[i] = remaining;
        }

        /* MQTT: poll for incoming messages (non-blocking, 10ms max) */
#if DCLAW_MQTT_ENABLED
        dclaw_mqtt_poll(10);
#endif

        /* Periodic tasks */
#if DCLAW_MQTT_ENABLED
        dclaw_mqtt_send_heartbeat();
        dclaw_mqtt_reconnect();
        dclaw_canary_tick();
        dclaw_lockdown_timeout_check();
#endif

        /* Local lockdown timeout — only active when MQTT is disabled.
         * When MQTT is enabled, the fleet-managed 24-hour timeout in
         * dclaw_lockdown_timeout_check() is authoritative.  Running both
         * caused the 1-hour local timeout to prematurely release a
         * lockdown the fleet intended to last longer. */
#if !DCLAW_MQTT_ENABLED
        {
            dclaw_state_t *st = dclaw_get_state();
            if (st->emergency.block_all_active) {
                if (block_all_activated_tick == 0) {
                    block_all_activated_tick = hal_tick_ms();
                } else {
                    uint64_t now = hal_tick_ms();
                    if ((now - block_all_activated_tick) > ((uint64_t)DCLAW_LOCKDOWN_TIMEOUT_SECS * 1000)) {
                        fprintf(stderr, "[DCLAW] WARN: lockdown timeout reached (%d seconds), auto-releasing\n",
                                DCLAW_LOCKDOWN_TIMEOUT_SECS);
                        st->emergency.block_all_active = false;
                        block_all_activated_tick = 0;
                    }
                }
            } else {
                block_all_activated_tick = 0;
            }
        }
#endif

        /* Flush audit on idle periods (no client activity) */
        if (ready == 0) {
            uint64_t now = hal_tick_ms();
            if (now - last_idle_flush >= (uint64_t)(DCLAW_AUDIT_FLUSH_SEC * 1000)) {
                dclaw_flush_audit();
                last_idle_flush = now;
            }
        }
    }

    /* Cleanup: close all client connections */
    for (int i = 0; i < num_clients; i++) {
        if (client_fds[i] >= 0)
            hal_ipc_socket_close(client_fds[i]);
    }
    hal_ipc_socket_close(server_fd);
    (void)unlink(ipc_socket_path);

    dclaw_shutdown();
    fprintf(stderr, "edge-connector: shutdown complete\n");
    return 0;
}
