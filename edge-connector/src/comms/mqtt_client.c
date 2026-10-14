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
#include "hmac_sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS == 1
#include <mbedtls/md.h>
#endif

/* Paho Embedded C MQTTClient — replaces hand-rolled MQTT 3.1.1 protocol code.
 * Platform header MQTTDclaw.h provides Timer/Network types integrated with
 * our TLS layer and monotonic clock. */
#include "MQTTClient.h"

/* Forward declarations for verdict_protocol.c accessor functions */
extern const uint8_t *dclaw_verdict_get_device_key(size_t *out_key_len);
extern bool dclaw_verdict_is_key_provisioned(void);

/*
 * MQTT client context.
 *
 * Paho manages protocol state (connect, subscribe, publish, keepalive)
 * internally. We keep our application-level state here: broker fallback,
 * reconnect backoff, heartbeat timing, pending verdict ring, and the
 * reconnect grace period.
 */

#define MQTT_DEFAULT_PORT    1883
#define MQTT_KEEPALIVE_SEC   60
#define MQTT_RECV_BUF_SIZE   4224  /* 4096 (max OTA blob) + 128 (MQTT header overhead) */
#define MQTT_SEND_BUF_SIZE   1024  /* heartbeats/verdicts are small */
#define MQTT_COMMAND_TIMEOUT 5000  /* 5s for connect/subscribe/publish */

typedef struct {
    MQTTClient      paho;          /* Paho client state */
    Network         net;           /* Paho network adapter (our TLS-aware I/O) */
    uint8_t         sendbuf[MQTT_SEND_BUF_SIZE];
    uint8_t         readbuf[MQTT_RECV_BUF_SIZE];
    bool            connected;
    uint8_t         broker_index;
    uint64_t        backoff_ms;
    uint64_t        last_attempt_tick;
    uint64_t        last_heartbeat_tick;
    char            session_id[32];
} mqtt_context_t;

static mqtt_context_t mqtt_ctx;

/*
 * For the rollback flag (which signals a safety-critical canary
 * rollback), keep the flag set for ROLLBACK_CLEAR_AFTER consecutive successful
 * heartbeat sends before clearing, so the information is transmitted at least
 * that many times for redundancy. Heartbeats use QoS 1 for broker ACK.
 */
#define ROLLBACK_CLEAR_AFTER 3
static uint8_t rollback_send_count = 0;

/*
 * Pending request tracking table — ring-buffer of {request_id, tool_hash} pairs.
 * When a verdict request is sent, the tool hash is stored here so that
 * the HMAC verifier can look it up when the response arrives.
 */
#ifndef DCLAW_PENDING_RING_SIZE
#define DCLAW_PENDING_RING_SIZE 16
#endif
#define MQTT_PENDING_RING_SIZE  DCLAW_PENDING_RING_SIZE

typedef struct {
    uint16_t request_id;
    uint8_t  tool_hash[32];
    bool     occupied;
} mqtt_pending_entry_t;

static mqtt_pending_entry_t pending_ring[MQTT_PENDING_RING_SIZE];
static uint8_t pending_ring_next = 0;

static uint32_t pending_evicted_count = 0;

extern void dclaw_verdict_mark_timeout(uint16_t request_id);

uint32_t dclaw_mqtt_pending_evicted_count(void) {
    return pending_evicted_count;
}

/* Reconnect grace period: after reconnect, if the last emergency was a
 * lockdown command, wait DCLAW_RECONNECT_GRACE_MS for any emergency
 * message before activating block_all. */
static bool s_replay_requested = false;
static uint64_t s_replay_deadline_ms = 0;
#define DCLAW_RECONNECT_GRACE_MS 60000

void dclaw_mqtt_pending_store(uint16_t request_id, const uint8_t *tool_hash) {
    mqtt_pending_entry_t *slot = &pending_ring[pending_ring_next];
    if (slot->occupied) {
        fprintf(stderr, "[DCLAW] WARNING: pending verdict slot %d evicted (ring full) — "
                "marking request_id=%u as timed out\n",
                pending_ring_next, slot->request_id);
        dclaw_verdict_mark_timeout(slot->request_id);
        pending_evicted_count++;
    }
    slot->request_id = request_id;
    memcpy(slot->tool_hash, tool_hash, 32);
    slot->occupied = true;
    pending_ring_next = (pending_ring_next + 1) % MQTT_PENDING_RING_SIZE;
}

static const uint8_t *dclaw_mqtt_pending_lookup(uint16_t request_id) {
    for (int i = 0; i < MQTT_PENDING_RING_SIZE; i++) {
        if (pending_ring[i].occupied && pending_ring[i].request_id == request_id) {
            return pending_ring[i].tool_hash;
        }
    }
    return NULL;
}

extern dclaw_state_t *dclaw_get_state(void);
extern const char *dclaw_config_get_broker(uint8_t index);
extern int dclaw_cbor_encode_heartbeat(uint8_t *buf, size_t *out_len, size_t buf_size);
extern int dclaw_cbor_encode_verdict_request(const dclaw_tool_request_t *req,
                                             uint16_t request_id, uint8_t session_risk,
                                             uint8_t *buf, size_t *out_len, size_t buf_size);
extern int dclaw_verdict_handle_response(const uint8_t *resp_buf, size_t resp_len,
                                         const uint8_t *pending_tool_hash);
extern int dclaw_apply_policy(const uint8_t *blob, uint32_t blob_len,
                              const uint8_t *signature);
extern int dclaw_apply_emergency(const uint8_t *msg, uint32_t msg_len);
extern bool dclaw_emergency_has_gap(uint32_t cloud_current_seq);
extern void dclaw_cache_flush_all(void);
extern void dclaw_emergency_persist(void);

/* === Paho Network I/O callbacks === */

/*
 * Read callback for Paho. Routes through TLS when active.
 * Must return the number of bytes actually read, or -1 on error.
 * Paho calls this in a loop until it has the full packet.
 */
int dclaw_paho_read(Network *net, unsigned char *buf, int len, int timeout_ms) {
#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS
    if (net->tls_active) {
        int ret = dclaw_tls_read(buf, (size_t)len, timeout_ms);
        if (ret == -2) return 0;  /* timeout → Paho retries */
        return (ret > 0) ? ret : -1;
    }
#endif
    struct pollfd pfd = { .fd = net->my_socket, .events = POLLIN };
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return 0;  /* timeout or error → Paho retries */

    int bytes = 0;
    while (bytes < len) {
        ssize_t n = read(net->my_socket, buf + bytes, (size_t)(len - bytes));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1; /* connection closed */
        bytes += (int)n;
    }
    return bytes;
}

/*
 * Write callback for Paho. Routes through TLS when active.
 * Must return the number of bytes written, or -1 on error.
 */
int dclaw_paho_write(Network *net, unsigned char *buf, int len, int timeout_ms) {
    (void)timeout_ms;
#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS
    if (net->tls_active) {
        int ret = dclaw_tls_write(buf, (size_t)len);
        return (ret >= 0 && (size_t)ret == (size_t)len) ? ret : -1;
    }
#endif
    int sent = 0;
    int attempts = 0;
    while (sent < len) {
        ssize_t n = write(net->my_socket, buf + sent, (size_t)(len - sent));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (++attempts > 100) return -1;
                struct pollfd pfd = { .fd = net->my_socket, .events = POLLOUT };
                poll(&pfd, 1, 100);
                continue;
            }
            return -1;
        }
        sent += (int)n;
    }
    return sent;
}

/* === TCP + TLS connection helpers === */

static int parse_broker_url(const char *url, char *host, size_t host_size,
                            uint16_t *port, bool *is_tls) {
    const char *p = url;
    *is_tls = false;

    if (strncmp(p, "mqtts://", 8) == 0) {
        p += 8;
        *is_tls = true;
    } else if (strncmp(p, "mqtt://", 7) == 0) {
        p += 7;
    }

    const char *colon = strchr(p, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - p);
        if (hlen >= host_size) return -1;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        errno = 0;
        char *end = NULL;
        unsigned long port_val = strtoul(colon + 1, &end, 10);
        if (errno != 0 || end == colon + 1 || (*end != '\0' && *end != '/' && *end != '?'))
            return -1;
        if (port_val == 0 || port_val > 65535)
            return -1;
        *port = (uint16_t)port_val;
    } else {
        size_t hlen = strlen(p);
        if (hlen >= host_size) return -1;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        *port = *is_tls ? 8883 : MQTT_DEFAULT_PORT;
    }
    return 0;
}

static int tcp_connect(const char *host, uint16_t port) {
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "[DCLAW-MQTT] DNS resolve failed for %s: %s\n",
                host, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0)
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) break;
        if (errno == EINPROGRESS) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            int poll_rc = poll(&pfd, 1, 5000);
            if (poll_rc > 0 && (pfd.revents & POLLOUT)) {
                int sock_err = 0;
                socklen_t errlen = sizeof(sock_err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &errlen);
                if (sock_err == 0) break;
            }
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        fprintf(stderr, "[DCLAW-MQTT] TCP connect failed to %s:%u\n", host, port);
        return -1;
    }

    /* Set blocking for Paho's synchronous connect/subscribe handshake.
     * Paho's read callback uses poll() internally for timeout handling. */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    return fd;
}

/* === MQTT message routing === */

static void mqtt_mark_disconnected(void) {
#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS
    if (mqtt_ctx.net.tls_active) {
        dclaw_tls_shutdown();
        mqtt_ctx.net.tls_active = false;
        mqtt_ctx.net.my_socket = -1;
    }
#endif
    if (mqtt_ctx.net.my_socket >= 0) {
        close(mqtt_ctx.net.my_socket);
        mqtt_ctx.net.my_socket = -1;
    }
    mqtt_ctx.connected = false;
    mqtt_ctx.paho.isconnected = 0;
    dclaw_get_state()->online = false;
}

static int build_topic(char *buf, size_t buf_size, const char *suffix) {
    dclaw_state_t *s = dclaw_get_state();
    int n = snprintf(buf, buf_size, "defenseclaw/%u/%u/%u/%s",
                     s->device.tenant_id, s->device.fleet_id,
                     s->device.device_id, suffix);
    return (n > 0 && (size_t)n < buf_size) ? 0 : -1;
}

/*
 * Route an incoming PUBLISH message by topic suffix.
 * Called by Paho's message handler callback.
 */
static void mqtt_route_publish(const char *topic, const uint8_t *payload,
                               size_t payload_len) {
    if (strncmp(topic, "defenseclaw/", 12) != 0) {
        fprintf(stderr, "[DCLAW-MQTT] WARNING: rejected message on unexpected topic prefix: %.64s\n",
                topic);
        return;
    }

    const char *suffix = strstr(topic, "verdict/resp");
    if (suffix) {
        if (payload_len >= 2) {
            uint16_t request_id = (uint16_t)((payload[0] << 8) | payload[1]);
            const uint8_t *tool_hash = dclaw_mqtt_pending_lookup(request_id);
            if (tool_hash) {
                dclaw_verdict_handle_response(payload, payload_len, tool_hash);
            } else {
                fprintf(stderr, "[DCLAW-MQTT] Verdict response for unknown request_id %u\n",
                        request_id);
            }
        }
        return;
    }

    suffix = strstr(topic, "ota/policy");
    if (suffix) {
        if (payload_len > 64) {
            uint32_t blob_len = (uint32_t)(payload_len - 64);
            const uint8_t *signature = payload + blob_len;
            dclaw_apply_policy(payload, blob_len, signature);
        }
        return;
    }

    suffix = strstr(topic, "ota/emergency");
    if (suffix) {
        int em_rc = dclaw_apply_emergency(payload, (uint32_t)payload_len);
        if (em_rc == 0) {
            s_replay_requested = false;
        }
        return;
    }
}

/*
 * Paho message-arrived callback. Extracts topic and payload, then
 * delegates to mqtt_route_publish() which contains our application logic.
 */
static void paho_message_handler(MessageData *data) {
    MQTTString *topic_str = data->topicName;
    char topic_buf[128];
    size_t tlen = 0;

    if (topic_str->cstring) {
        tlen = strlen(topic_str->cstring);
    } else {
        tlen = (size_t)topic_str->lenstring.len;
    }
    if (tlen >= sizeof(topic_buf)) {
        fprintf(stderr, "[DCLAW-MQTT] WARNING: rejecting message with topic >%zu bytes\n",
                sizeof(topic_buf) - 1);
        return;
    }
    if (topic_str->cstring) {
        memcpy(topic_buf, topic_str->cstring, tlen);
    } else {
        memcpy(topic_buf, topic_str->lenstring.data, tlen);
    }
    topic_buf[tlen] = '\0';

    mqtt_route_publish(topic_buf,
                       (const uint8_t *)data->message->payload,
                       data->message->payloadlen);
}

/* === Public API === */

int dclaw_mqtt_init(void) {
    memset(&mqtt_ctx, 0, sizeof(mqtt_ctx));
    mqtt_ctx.connected = false;
    mqtt_ctx.backoff_ms = 1000;
    mqtt_ctx.net.my_socket = -1;

    NetworkInit(&mqtt_ctx.net);
    MQTTClientInit(&mqtt_ctx.paho, &mqtt_ctx.net,
                   MQTT_COMMAND_TIMEOUT,
                   mqtt_ctx.sendbuf, sizeof(mqtt_ctx.sendbuf),
                   mqtt_ctx.readbuf, sizeof(mqtt_ctx.readbuf));
    return 0;
}

int dclaw_mqtt_connect(void) {
    if (mqtt_ctx.connected) return 0;

    const char *broker_url = dclaw_config_get_broker(mqtt_ctx.broker_index);
    if (!broker_url) {
        dclaw_get_state()->online = false;
        return -1;
    }

    mqtt_ctx.last_attempt_tick = hal_tick_ms();

    char host[128];
    uint16_t port;
    bool is_tls;

    if (parse_broker_url(broker_url, host, sizeof(host), &port, &is_tls) != 0) {
        fprintf(stderr, "[DCLAW-MQTT] Bad broker URL: %s\n", broker_url);
        return -1;
    }

#if !defined(DCLAW_HAS_MBEDTLS) || !DCLAW_HAS_MBEDTLS
    if (is_tls) {
        fprintf(stderr, "[DCLAW-MQTT] ERROR: mqtts:// requested but mbedTLS not available. "
                "Refusing to connect over plain TCP. Build with DCLAW_HAS_MBEDTLS=1 "
                "or use mqtt:// for development only.\n");
        return -1;
    }
#endif

#if !DCLAW_DEV_MODE
    if (!is_tls) {
        fprintf(stderr, "[DCLAW-MQTT] ERROR: Plaintext MQTT refused in production. "
                "Use mqtts:// URL. Rebuild with -DDCLAW_DEV_MODE=ON for development.\n");
        return -1;
    }
#endif

    /* Step 1: TCP connect */
    int fd = tcp_connect(host, port);
    if (fd < 0) return -1;

    /* Step 2: TLS handshake (mqtts:// only) */
    mqtt_ctx.net.my_socket = fd;
    mqtt_ctx.net.tls_active = false;

#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS
    if (is_tls) {
        if (dclaw_tls_init() != 0) {
            fprintf(stderr, "[DCLAW-MQTT] TLS engine initialization failed\n");
            close(fd);
            mqtt_ctx.net.my_socket = -1;
            return -1;
        }
        if (dclaw_tls_connect(fd, host) != 0) {
            fprintf(stderr, "[DCLAW-MQTT] TLS handshake failed\n");
            dclaw_tls_shutdown();
            /* fd already closed by dclaw_tls_shutdown -> mbedtls_net_free */
            mqtt_ctx.net.my_socket = -1;
            return -1;
        }
        mqtt_ctx.net.tls_active = true;
        fprintf(stderr, "[DCLAW-MQTT] TLS session established\n");
    }
#endif

    /* Step 3: MQTT CONNECT via Paho */
    dclaw_state_t *s = dclaw_get_state();
    char client_id[32];
    snprintf(client_id, sizeof(client_id), "dclaw-%u", s->device.device_id);

    const char *mqtt_user = getenv("DCLAW_MQTT_USER");
    const char *mqtt_pass = getenv("DCLAW_MQTT_PASS");

    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    opts.clientID.cstring = client_id;
    opts.keepAliveInterval = MQTT_KEEPALIVE_SEC;
    opts.cleansession = 1;
    opts.MQTTVersion = 4; /* MQTT 3.1.1 */

    if (mqtt_user && mqtt_user[0])
        opts.username.cstring = (char *)mqtt_user;
    if (mqtt_pass && mqtt_pass[0])
        opts.password.cstring = (char *)mqtt_pass;

    if (MQTTConnect(&mqtt_ctx.paho, &opts) != SUCCESS) {
        fprintf(stderr, "[DCLAW-MQTT] CONNECT/CONNACK handshake failed\n");
        mqtt_mark_disconnected();
        return -1;
    }

    /* Step 4: Subscribe to device topics via Paho */
    char topic[128];

    /* Subscribe to verdict responses (device-specific) */
    snprintf(topic, sizeof(topic), "defenseclaw/%u/%u/%u/verdict/resp",
             s->device.tenant_id, s->device.fleet_id, s->device.device_id);
    if (MQTTSubscribe(&mqtt_ctx.paho, topic, QOS1, paho_message_handler) != SUCCESS) {
        fprintf(stderr, "[DCLAW-MQTT] Subscribe to verdict/resp failed\n");
        mqtt_mark_disconnected();
        return -1;
    }

    /* Subscribe to OTA policy updates (fleet-wide) */
    snprintf(topic, sizeof(topic), "defenseclaw/%u/%u/ota/policy",
             s->device.tenant_id, s->device.fleet_id);
    if (MQTTSubscribe(&mqtt_ctx.paho, topic, QOS1, paho_message_handler) != SUCCESS) {
        fprintf(stderr, "[DCLAW-MQTT] Subscribe to ota/policy failed\n");
        mqtt_mark_disconnected();
        return -1;
    }

    /* Subscribe to emergency broadcasts (fleet-wide) */
    snprintf(topic, sizeof(topic), "defenseclaw/%u/%u/ota/emergency",
             s->device.tenant_id, s->device.fleet_id);
    if (MQTTSubscribe(&mqtt_ctx.paho, topic, QOS1, paho_message_handler) != SUCCESS) {
        fprintf(stderr, "[DCLAW-MQTT] Subscribe to ota/emergency failed\n");
        mqtt_mark_disconnected();
        return -1;
    }

    /* Best-effort scrub MQTT password from environment */
    dclaw_scrub_env("DCLAW_MQTT_PASS");

    /* Set socket to non-blocking for the event loop.
     * Paho's read callback uses poll() internally so this is safe. */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    mqtt_ctx.connected = true;
    dclaw_get_state()->online = true;

    snprintf(mqtt_ctx.session_id, sizeof(mqtt_ctx.session_id), "%u",
             dclaw_get_state()->device.device_id);

    /* Step 5: Publish registration message (HMAC-signed if key is provisioned) */
    {
        uint8_t reg_buf[64];
        size_t reg_len;
        if (dclaw_cbor_encode_heartbeat(reg_buf, &reg_len, sizeof(reg_buf)) == 0) {
            char reg_topic[128];
            if (build_topic(reg_topic, sizeof(reg_topic), "register") == 0) {
                size_t rk_len = 0;
                if (dclaw_verdict_is_key_provisioned()) {
                    const uint8_t *rk = dclaw_verdict_get_device_key(&rk_len);
                    if (rk && rk_len > 0) {
                        uint8_t reg_hmac[32] = {0};
#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS == 1
                        mbedtls_md_context_t rctx;
                        const mbedtls_md_info_t *rmd = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
                        mbedtls_md_init(&rctx);
                        mbedtls_md_setup(&rctx, rmd, 1);
                        mbedtls_md_hmac_starts(&rctx, rk, rk_len);
                        mbedtls_md_hmac_update(&rctx, (const uint8_t *)reg_topic, strlen(reg_topic));
                        mbedtls_md_hmac_update(&rctx, reg_buf, 32);
                        mbedtls_md_hmac_finish(&rctx, reg_hmac);
                        mbedtls_md_free(&rctx);
#else
                        {
                            size_t rt_len = strlen(reg_topic);
                            uint8_t rtmp[128 + 32];
                            if (rt_len + 32 <= sizeof(rtmp)) {
                                memcpy(rtmp, reg_topic, rt_len);
                                memcpy(rtmp + rt_len, reg_buf, 32);
                                dclaw_hmac_sha256(rk, rk_len, rtmp, rt_len + 32, reg_hmac);
                            }
                        }
#endif
                        memcpy(reg_buf + 32, reg_hmac, 32);
                        reg_len = 64;
                    }
                }

                MQTTMessage reg_msg = {
                    .qos = QOS1,
                    .retained = 0,
                    .dup = 0,
                    .payload = reg_buf,
                    .payloadlen = reg_len,
                };
                if (MQTTPublish(&mqtt_ctx.paho, reg_topic, &reg_msg) != SUCCESS) {
                    fprintf(stderr, "[DCLAW-MQTT] Failed to publish registration message\n");
                } else {
                    fprintf(stderr, "[DCLAW-MQTT] Registration message sent on %s\n", reg_topic);
                }
            }
        }
    }

    fprintf(stderr, "[DCLAW-MQTT] Connected to %s:%u\n", host, port);
    return 0;
}

int dclaw_mqtt_reconnect(void) {
    if (mqtt_ctx.connected) return 0;

    uint64_t now = hal_tick_ms();
    if (now - mqtt_ctx.last_attempt_tick < mqtt_ctx.backoff_ms)
        return -1;

    int rc = dclaw_mqtt_connect();
    if (rc != 0) {
        mqtt_ctx.broker_index++;
        if (!dclaw_config_get_broker(mqtt_ctx.broker_index)) {
            mqtt_ctx.broker_index = 0;
            mqtt_ctx.backoff_ms *= 2;
            if (mqtt_ctx.backoff_ms > 300000) mqtt_ctx.backoff_ms = 300000;
        }
    } else {
        mqtt_ctx.backoff_ms = 1000;
        mqtt_ctx.broker_index = 0;

        dclaw_state_t *rs = dclaw_get_state();
        if (rs->emergency.initialized && rs->emergency.last_was_lockdown) {
            fprintf(stderr, "[DCLAW-MQTT] reconnect: lockdown grace period started "
                    "(last_seen_seq=%u, grace=%u ms)\n",
                    rs->emergency.last_seen_seq, (unsigned)DCLAW_RECONNECT_GRACE_MS);
            s_replay_requested = true;
            s_replay_deadline_ms = hal_tick_ms() + DCLAW_RECONNECT_GRACE_MS;
            rs->emergency.replay_requested = true;
        }
    }
    return rc;
}

int dclaw_mqtt_publish(const char *topic, const void *payload, size_t len, uint8_t qos) {
    if (!mqtt_ctx.connected) return -1;

    MQTTMessage msg = {
        .qos = (enum QoS)qos,
        .retained = 0,
        .dup = 0,
        .payload = (void *)payload,
        .payloadlen = len,
    };

    int rc = MQTTPublish(&mqtt_ctx.paho, topic, &msg);
    if (rc != SUCCESS) {
        fprintf(stderr, "[DCLAW-MQTT] Publish failed (rc=%d), marking disconnected\n", rc);
        mqtt_mark_disconnected();
        return -1;
    }
    return 0;
}

int dclaw_mqtt_poll(int timeout_ms) {
    if (!mqtt_ctx.connected) return -1;

    /* MQTTYield handles: read packets, dispatch to message handlers,
     * send PUBACK for QoS 1, keepalive PINGREQ/PINGRESP */
    int rc = MQTTYield(&mqtt_ctx.paho, timeout_ms);
    if (rc != SUCCESS) {
        fprintf(stderr, "[DCLAW-MQTT] Connection lost (yield rc=%d)\n", rc);
        mqtt_mark_disconnected();
        return -1;
    }

    /* Reconnect grace period check */
    if (s_replay_requested && hal_tick_ms() > s_replay_deadline_ms) {
        fprintf(stderr, "[DCLAW-MQTT] WARN: no emergency replay within grace period, activating block_all\n");
        dclaw_state_t *gs = dclaw_get_state();
        gs->emergency.block_all_active = true;
        s_replay_requested = false;
        dclaw_cache_flush_all();
        dclaw_emergency_persist();
    }

    return 0;
}

bool dclaw_mqtt_is_connected(void) {
    return mqtt_ctx.connected && MQTTIsConnected(&mqtt_ctx.paho);
}

const char *dclaw_mqtt_get_session_id(void) {
    return mqtt_ctx.session_id;
}

/*
 * Heartbeat publish (called from event loop).
 *
 * When a per-device key is provisioned, append an HMAC-SHA256 tag
 * over topic + payload, making the total MQTT payload 64 bytes.
 */
int dclaw_mqtt_send_heartbeat(void) {
    if (!dclaw_mqtt_is_connected()) return -1;

    uint64_t now = hal_tick_ms();
    if (now - mqtt_ctx.last_heartbeat_tick < (uint64_t)(DCLAW_HEARTBEAT_INTERVAL_SEC * 1000))
        return 0;
    mqtt_ctx.last_heartbeat_tick = now;

    uint8_t hb_buf[64];
    size_t hb_len;
    if (dclaw_cbor_encode_heartbeat(hb_buf, &hb_len, sizeof(hb_buf)) != 0) return -1;

    char topic[128];
    if (build_topic(topic, sizeof(topic), "heartbeat") != 0) return -1;

    /* Append HMAC-SHA256 tag if a real device key is provisioned */
    size_t key_len = 0;
    if (dclaw_verdict_is_key_provisioned()) {
        const uint8_t *device_key = dclaw_verdict_get_device_key(&key_len);
        if (device_key && key_len > 0) {
            uint8_t hmac_tag[32];
#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS == 1
            mbedtls_md_context_t ctx;
            const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            mbedtls_md_init(&ctx);
            mbedtls_md_setup(&ctx, md_info, 1);
            mbedtls_md_hmac_starts(&ctx, device_key, key_len);
            mbedtls_md_hmac_update(&ctx, (const uint8_t *)topic, strlen(topic));
            mbedtls_md_hmac_update(&ctx, hb_buf, 32);
            mbedtls_md_hmac_finish(&ctx, hmac_tag);
            mbedtls_md_free(&ctx);
#else
            {
                size_t topic_len = strlen(topic);
                uint8_t tmp[128 + 32];
                if (topic_len + 32 <= sizeof(tmp)) {
                    memcpy(tmp, topic, topic_len);
                    memcpy(tmp + topic_len, hb_buf, 32);
                    dclaw_hmac_sha256(device_key, key_len, tmp, topic_len + 32, hmac_tag);
                } else {
                    return -1;
                }
            }
#endif
            memcpy(hb_buf + 32, hmac_tag, 32);
            hb_len = 64;
        }
    }

    int rc = dclaw_mqtt_publish(topic, hb_buf, hb_len, 1);

    if (rc == 0) {
        dclaw_state_t *st = dclaw_get_state();
        if (st->rollback_pending) {
            rollback_send_count++;
            if (rollback_send_count >= ROLLBACK_CLEAR_AFTER) {
                st->rollback_pending = false;
                rollback_send_count = 0;
            }
        }
    } else {
        rollback_send_count = 0;
    }

    return rc;
}

/* Verdict request publish.
 * Append HMAC-SHA256(device_key, topic + cbor_payload) so the
 * Go fleet manager can verify keyed devices. Without this, the bridge
 * splits the payload at len-32 and rejects the HMAC mismatch. */
int dclaw_mqtt_send_verdict_request(const dclaw_tool_request_t *req,
                                    uint16_t request_id) {
    if (!dclaw_mqtt_is_connected()) return -1;

    uint8_t cbor_buf[512 + 32]; /* CBOR + optional 32-byte HMAC */
    size_t cbor_len;
    if (dclaw_cbor_encode_verdict_request(req, request_id, 0,
                                          cbor_buf, &cbor_len, 512) != 0) {
        return -1;
    }

    char topic[128];
    if (build_topic(topic, sizeof(topic), "verdict/req") != 0) return -1;

    /* Append HMAC if device key is provisioned */
    size_t send_len = cbor_len;
    size_t key_len = 0;
    if (dclaw_verdict_is_key_provisioned()) {
        const uint8_t *dk = dclaw_verdict_get_device_key(&key_len);
        if (dk && key_len > 0) {
            uint8_t vr_hmac[32];
#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS == 1
            mbedtls_md_context_t mctx;
            const mbedtls_md_info_t *mdi = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            mbedtls_md_init(&mctx);
            mbedtls_md_setup(&mctx, mdi, 1);
            mbedtls_md_hmac_starts(&mctx, dk, key_len);
            mbedtls_md_hmac_update(&mctx, (const uint8_t *)topic, strlen(topic));
            mbedtls_md_hmac_update(&mctx, cbor_buf, cbor_len);
            mbedtls_md_hmac_finish(&mctx, vr_hmac);
            mbedtls_md_free(&mctx);
#else
            {
                size_t tlen = strlen(topic);
                uint8_t vtmp[128 + 512];
                if (tlen + cbor_len <= sizeof(vtmp)) {
                    memcpy(vtmp, topic, tlen);
                    memcpy(vtmp + tlen, cbor_buf, cbor_len);
                    dclaw_hmac_sha256(dk, key_len, vtmp, tlen + cbor_len, vr_hmac);
                } else {
                    fprintf(stderr, "[DCLAW-MQTT] ERROR: verdict request too large for HMAC buffer\n");
                    return -1;
                }
            }
#endif
            memcpy(cbor_buf + cbor_len, vr_hmac, 32);
            send_len = cbor_len + 32;
        }
    }

    return dclaw_mqtt_publish(topic, cbor_buf, send_len, 1);
}
