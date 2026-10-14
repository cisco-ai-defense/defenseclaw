/*
 * Paho Embedded C platform adapter for DefenseClaw Edge Connector.
 *
 * Provides the Timer and Network types that Paho's MQTTClient.h expects.
 * Timer uses CLOCK_MONOTONIC (not gettimeofday which drifts on NTP sync).
 * Network I/O routes through our TLS layer when active, raw sockets otherwise.
 *
 * This file replaces Paho's stock linux/MQTTLinux.h — it is selected via
 *   -DMQTTCLIENT_PLATFORM_HEADER=MQTTDclaw.h
 * in CMakeLists.txt.
 */

#ifndef MQTT_DCLAW_PLATFORM_H
#define MQTT_DCLAW_PLATFORM_H

#include <time.h>
#include <stdint.h>
#include <stdbool.h>

/* Timer — uses CLOCK_MONOTONIC for NTP-resilient timeouts. */
typedef struct Timer {
    uint64_t end_ms;   /* absolute monotonic deadline in milliseconds */
} Timer;

static inline uint64_t _dclaw_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static inline void TimerInit(Timer *t) {
    t->end_ms = 0;
}

static inline char TimerIsExpired(Timer *t) {
    return (t->end_ms == 0) ? 1 : (_dclaw_mono_ms() >= t->end_ms);
}

static inline void TimerCountdownMS(Timer *t, unsigned int ms) {
    t->end_ms = _dclaw_mono_ms() + ms;
}

static inline void TimerCountdown(Timer *t, unsigned int secs) {
    t->end_ms = _dclaw_mono_ms() + (uint64_t)secs * 1000;
}

static inline int TimerLeftMS(Timer *t) {
    uint64_t now = _dclaw_mono_ms();
    if (t->end_ms <= now) return 0;
    uint64_t left = t->end_ms - now;
    return (left > (uint64_t)0x7FFFFFFF) ? 0x7FFFFFFF : (int)left;
}

/* Network — Paho calls mqttread/mqttwrite; we route through TLS or raw socket. */
typedef struct Network {
    int my_socket;
    bool tls_active;
    int (*mqttread)(struct Network *, unsigned char *, int, int);
    int (*mqttwrite)(struct Network *, unsigned char *, int, int);
} Network;

/* Implemented in mqtt_client.c */
int dclaw_paho_read(Network *net, unsigned char *buf, int len, int timeout_ms);
int dclaw_paho_write(Network *net, unsigned char *buf, int len, int timeout_ms);

static inline void NetworkInit(Network *n) {
    n->my_socket = -1;
    n->tls_active = false;
    n->mqttread = dclaw_paho_read;
    n->mqttwrite = dclaw_paho_write;
}

#endif /* MQTT_DCLAW_PLATFORM_H */
