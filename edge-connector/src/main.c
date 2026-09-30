#include "defenseclaw.h"
#include "platform.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#ifndef DCLAW_IPC_SOCKET_PATH
#define DCLAW_IPC_SOCKET_PATH "/tmp/defenseclaw.sock"
#endif

#define DCLAW_MAX_IPC_CLIENTS 8
#define DCLAW_IPC_BUF_SIZE    (DCLAW_IPC_MAX_PAYLOAD + 1)

/* External module functions */
extern int  dclaw_mqtt_init(void);
extern int  dclaw_mqtt_connect(void);
extern int  dclaw_mqtt_send_heartbeat(void);
extern int  dclaw_mqtt_reconnect(void);
extern void dclaw_canary_tick(void);
extern int  dclaw_ipc_parse_request(const char *json, size_t json_len,
                                    dclaw_tool_request_t *out);

static volatile bool g_running = true;

static void signal_handler(int sig) {
    (void)sig;
    g_running = false;
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
 * Returns 0 on success, -1 on write failure. */
static int write_verdict_response(int fd, const dclaw_verdict_t *v) {
    char resp[256];
    int n = snprintf(resp, sizeof(resp),
        "{\"jsonrpc\":\"2.0\",\"result\":{\"action\":\"%s\","
        "\"reason\":%u,\"severity\":%u,\"cached\":%s},\"id\":1}\n",
        action_string(v->action),
        (unsigned)v->reason,
        (unsigned)v->severity,
        v->from_cache ? "true" : "false");
    if (n <= 0 || (size_t)n >= sizeof(resp)) return -1;
    ssize_t w = write(fd, resp, (size_t)n);
    return (w == n) ? 0 : -1;
}

int main(void) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    dclaw_device_info_t info = {
        .tenant_id = 1,
        .fleet_id = 1,
        .device_id = 0, /* populated from config */
        .policy_version = 0,
        .fw_version = 1,
        .hw_profile = 2, /* LINUX_SBC */
        .capabilities = 0xFF,
    };

    if (dclaw_init(&info) != 0) {
        fprintf(stderr, "edge-connector: init failed\n");
        return 1;
    }

    /* Initialize MQTT and attempt initial connection */
    dclaw_mqtt_init();
    dclaw_mqtt_connect();

    /* Create the IPC Unix domain socket */
    int server_fd = hal_ipc_socket_create(DCLAW_IPC_SOCKET_PATH);
    if (server_fd < 0) {
        fprintf(stderr, "edge-connector: failed to create IPC socket at %s\n",
                DCLAW_IPC_SOCKET_PATH);
        dclaw_shutdown();
        return 1;
    }

    fprintf(stderr, "edge-connector: running (profile=STANDARD, ipc=%s)\n",
            DCLAW_IPC_SOCKET_PATH);

    /* pollfd array: slot 0 = server socket, slots 1..MAX = client connections */
    struct pollfd fds[1 + DCLAW_MAX_IPC_CLIENTS];
    int client_fds[DCLAW_MAX_IPC_CLIENTS];
    int num_clients = 0;

    memset(fds, 0, sizeof(fds));
    for (int i = 0; i < DCLAW_MAX_IPC_CLIENTS; i++)
        client_fds[i] = -1;

    fds[0].fd = server_fd;
    fds[0].events = POLLIN;

    uint32_t last_idle_flush = hal_tick_ms();

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
                if (num_clients < DCLAW_MAX_IPC_CLIENTS) {
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

            char buf[DCLAW_IPC_BUF_SIZE];
            ssize_t n = read(client_fds[i], buf, sizeof(buf) - 1);
            if (n <= 0) {
                /* Client disconnected or error */
                hal_ipc_socket_close(client_fds[i]);
                client_fds[i] = client_fds[num_clients - 1];
                client_fds[num_clients - 1] = -1;
                num_clients--;
                i--; /* re-check swapped slot */
                continue;
            }
            buf[n] = '\0';

            /* Parse JSON-RPC request and evaluate */
            dclaw_tool_request_t req;
            if (dclaw_ipc_parse_request(buf, (size_t)n, &req) == 0) {
                dclaw_verdict_t verdict = dclaw_evaluate(&req);
                write_verdict_response(client_fds[i], &verdict);
            } else {
                /* Malformed request — send error response */
                const char *err =
                    "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,"
                    "\"message\":\"Invalid Request\"},\"id\":null}\n";
                write(client_fds[i], err, strlen(err));
            }
        }

        /* Periodic tasks */
        dclaw_mqtt_send_heartbeat();
        dclaw_mqtt_reconnect();
        dclaw_canary_tick();

        /* Flush audit on idle periods (no client activity) */
        if (ready == 0) {
            uint32_t now = hal_tick_ms();
            if (now - last_idle_flush >= (uint32_t)(DCLAW_AUDIT_FLUSH_SEC * 1000)) {
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
    unlink(DCLAW_IPC_SOCKET_PATH);

    dclaw_shutdown();
    fprintf(stderr, "edge-connector: shutdown complete\n");
    return 0;
}
