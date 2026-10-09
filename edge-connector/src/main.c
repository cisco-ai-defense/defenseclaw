#include "defenseclaw.h"
#include "platform.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>

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

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static const char *action_string(dclaw_action_t a) {
    switch (a) {
        case DCLAW_ACTION_ALLOW:    return "allow";
        case DCLAW_ACTION_BLOCK:    return "block";
        case DCLAW_ACTION_WARN:     return "warn";
        case DCLAW_ACTION_ESCALATE: return "escalate";
    }
    return "unknown";
}

/* Write a JSON-RPC response for a verdict back to the client fd.
 * Loops on partial writes to ensure the full response is sent.
 * Returns 0 on success, -1 on write failure. */
static int write_verdict_response(int fd, const dclaw_verdict_t *v, int32_t request_id) {
    char resp[256];
    int n = snprintf(resp, sizeof(resp),
        "{\"jsonrpc\":\"2.0\",\"result\":{\"action\":\"%s\","
        "\"reason\":%u,\"severity\":%u,\"cached\":%s},\"id\":%d}\n",
        action_string(v->action),
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

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* L-3 fix: Ignore SIGPIPE to prevent the process from being killed when
     * writing to a broken IPC socket.  A broken socket write (e.g., client
     * disconnected mid-response) generates SIGPIPE whose default action is
     * process termination.  Ignoring it causes write() to return EPIPE
     * instead, which our write loop already handles gracefully. */
    signal(SIGPIPE, SIG_IGN);

    const char *env_tenant = getenv("DCLAW_TENANT_ID");
    const char *env_fleet  = getenv("DCLAW_FLEET_ID");
    const char *env_device = getenv("DCLAW_DEVICE_ID");

    dclaw_device_info_t info = {
        .tenant_id = env_tenant ? (uint16_t)strtoul(env_tenant, NULL, 10) : 1,
        .fleet_id  = env_fleet  ? (uint16_t)strtoul(env_fleet, NULL, 10)  : 1,
        .device_id = env_device ? (uint32_t)strtoul(env_device, NULL, 10) : 0,
        .policy_version = 0,
        .fw_version = 1,
        .hw_profile = 2, /* LINUX_SBC */
        .capabilities = 0xFF,
    };

    if (dclaw_init(&info) != 0) {
        fprintf(stderr, "edge-connector: init failed\n");
        return 1;
    }

    /* P1 fix: Set IPC peer expected UID/GID so non-root users can connect.
     * By default, accept connections from the same user that started the
     * daemon.  Env vars DCLAW_IPC_ALLOWED_UID / DCLAW_IPC_ALLOWED_GID
     * override this for multi-user setups (e.g., daemon runs as root but
     * CLI runs as a service account). */
    {
        dclaw_state_t *st = dclaw_get_state();
        const char *env_uid = getenv("DCLAW_IPC_ALLOWED_UID");
        const char *env_gid = getenv("DCLAW_IPC_ALLOWED_GID");
        st->ipc_peer.expected_uid = env_uid ? (uint32_t)strtoul(env_uid, NULL, 10) : (uint32_t)getuid();
        st->ipc_peer.expected_gid = env_gid ? (uint32_t)strtoul(env_gid, NULL, 10) : (uint32_t)getgid();
    }

    /* Resolve IPC socket path: env var override, then compile-time default */
    const char *env_ipc = getenv("DCLAW_IPC_SOCKET_PATH");
    const char *ipc_socket_path = (env_ipc && env_ipc[0] != '\0')
                                  ? env_ipc : DCLAW_IPC_SOCKET_PATH_DEFAULT;

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
                /* Client disconnected or error */
                hal_ipc_socket_close(client_fds[i]);
                client_fds[i] = client_fds[num_clients - 1];
                client_buf_len[i] = client_buf_len[num_clients - 1];
                memcpy(client_buf[i], client_buf[num_clients - 1], client_buf_len[i]);
                client_fds[num_clients - 1] = -1;
                client_buf_len[num_clients - 1] = 0;
                num_clients--;
                i--; /* re-check swapped slot */
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

                /* BLK-2 fix: IPC lockdown release requires HMAC authentication.
                 * Format: "release_lockdown:<64-hex-hmac>\n"
                 * HMAC = HMAC-SHA256(audit_key, "release_lockdown")
                 * This prevents an unprivileged local process from clearing
                 * lockdown. The audit key serves as the shared secret. */
#if DCLAW_MQTT_ENABLED
                if (msg_len >= 16 && memcmp(base, "release_lockdown", 16) == 0) {
                    bool authenticated = false;
                    if (msg_len == 16) {
                        /* No HMAC provided — only allow in dev mode */
#if DCLAW_DEV_MODE
                        authenticated = true;
#else
                        const char *deny = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000,\"message\":\"HMAC required for lockdown release in production\"},\"id\":null}\n";
                        if (write(client_fds[i], deny, strlen(deny)) < 0) { /* best-effort */ }
#endif
                    } else if (msg_len == 81 && base[16] == ':') {
                        /* Verify HMAC-SHA256(audit_key, "release_lockdown") */
                        uint8_t provided[32];
                        bool hex_ok = true;
                        for (int h = 0; h < 32; h++) {
                            int hi = base[17 + h*2], lo = base[18 + h*2];
                            int hv = (hi >= '0' && hi <= '9') ? hi-'0' : (hi >= 'a' && hi <= 'f') ? hi-'a'+10 : (hi >= 'A' && hi <= 'F') ? hi-'A'+10 : -1;
                            int lv = (lo >= '0' && lo <= '9') ? lo-'0' : (lo >= 'a' && lo <= 'f') ? lo-'a'+10 : (lo >= 'A' && lo <= 'F') ? lo-'A'+10 : -1;
                            if (hv < 0 || lv < 0) { hex_ok = false; break; }
                            provided[h] = (uint8_t)((hv << 4) | lv);
                        }
                        if (hex_ok) {
                            extern const uint8_t *dclaw_audit_get_key(size_t *out_len);
                            size_t key_len = 0;
                            const uint8_t *akey = dclaw_audit_get_key(&key_len);
                            if (akey && key_len == 32) {
                                uint8_t expected[32];
                                extern void dclaw_hmac_sha256(const uint8_t *key, size_t kl,
                                    const uint8_t *msg, size_t ml, uint8_t *out);
                                dclaw_hmac_sha256(akey, key_len,
                                    (const uint8_t *)"release_lockdown", 16, expected);
                                volatile uint8_t diff = 0;
                                for (int h = 0; h < 32; h++) diff |= provided[h] ^ expected[h];
                                authenticated = (diff == 0);
                                if (!authenticated) {
                                    fprintf(stderr, "[DCLAW] WARNING: IPC lockdown release HMAC mismatch\n");
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
        /* CRT-5 fix: Check if lockdown has exceeded 24-hour timeout */
        dclaw_lockdown_timeout_check();
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
