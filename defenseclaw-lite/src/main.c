#include "defenseclaw.h"
#include "platform.h"
#include <signal.h>
#include <stdio.h>
#include <time.h>

static volatile bool g_running = true;

static void signal_handler(int sig) {
    (void)sig;
    g_running = false;
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
        fprintf(stderr, "defenseclaw-lite: init failed\n");
        return 1;
    }

    fprintf(stderr, "defenseclaw-lite: running (profile=STANDARD)\n");

    while (g_running) {
        hal_watchdog_feed();
        /* Event loop: IPC accept + MQTT poll handled in respective modules */
        /* For Phase 1 on Linux, we use epoll in the real implementation. */
        /* This skeleton demonstrates the lifecycle. */
        struct timespec ts = {0, 10000000}; /* 10ms */
        nanosleep(&ts, NULL);
    }

    dclaw_shutdown();
    fprintf(stderr, "defenseclaw-lite: shutdown complete\n");
    return 0;
}
