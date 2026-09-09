#include "defenseclaw.h"
#include "platform.h"
#include <string.h>
#include <stdio.h>

/*
 * MQTT 5.0 client for DefenseClaw Lite.
 *
 * Phase 1 implementation: connection state machine with broker fallback.
 * TLS/mTLS handshake uses mbedTLS (when available).
 * Without mbedTLS: operates in plaintext mode for development/testing only.
 *
 * Production deployment requires DCLAW_HAS_MBEDTLS=1.
 */

typedef enum {
    MQTT_STATE_DISCONNECTED,
    MQTT_STATE_CONNECTING,
    MQTT_STATE_CONNECTED,
    MQTT_STATE_RECONNECTING,
} mqtt_state_t;

typedef struct {
    mqtt_state_t state;
    uint8_t      broker_index;
    uint32_t     backoff_ms;
    uint32_t     last_attempt_tick;
    uint32_t     last_heartbeat_tick;
    uint16_t     next_packet_id;
    int          socket_fd;
    char         session_id[32];
} mqtt_context_t;

static mqtt_context_t mqtt_ctx;

extern dclaw_state_t *dclaw_get_state(void);
extern const char *dclaw_config_get_broker(uint8_t index);
extern int dclaw_cbor_encode_heartbeat(uint8_t *buf, size_t *out_len, size_t buf_size);
extern int dclaw_cbor_encode_verdict_request(const dclaw_tool_request_t *req,
                                             uint16_t request_id, uint8_t session_risk,
                                             uint8_t *buf, size_t *out_len, size_t buf_size);

/* Topic construction helper */
static int build_topic(char *buf, size_t buf_size, const char *suffix) {
    dclaw_state_t *s = dclaw_get_state();
    int n = snprintf(buf, buf_size, "defenseclaw/%u/%u/%u/%s",
                     s->device.tenant_id, s->device.fleet_id,
                     s->device.device_id, suffix);
    return (n > 0 && (size_t)n < buf_size) ? 0 : -1;
}

int dclaw_mqtt_init(void) {
    memset(&mqtt_ctx, 0, sizeof(mqtt_ctx));
    mqtt_ctx.state = MQTT_STATE_DISCONNECTED;
    mqtt_ctx.backoff_ms = 1000;
    mqtt_ctx.next_packet_id = 1;
    mqtt_ctx.socket_fd = -1;
    return 0;
}

int dclaw_mqtt_connect(void) {
    if (mqtt_ctx.state == MQTT_STATE_CONNECTED) return 0;

    const char *broker_url = dclaw_config_get_broker(mqtt_ctx.broker_index);
    if (!broker_url) {
        /* No more brokers to try — enter offline mode */
        dclaw_get_state()->online = false;
        mqtt_ctx.state = MQTT_STATE_DISCONNECTED;
        return -1;
    }

    mqtt_ctx.state = MQTT_STATE_CONNECTING;
    mqtt_ctx.last_attempt_tick = hal_tick_ms();

    /*
     * Phase 1 connection sequence:
     * 1. TCP connect to broker host:port
     * 2. TLS handshake (mTLS with device cert + CA)
     * 3. MQTT CONNECT packet (v5, clean start=false)
     * 4. Wait for CONNACK
     * 5. Subscribe to device topics
     *
     * This is stubbed for local development without mbedTLS.
     * Integration test (Task 14) will use a real MQTT broker.
     */

#if DCLAW_HAS_MBEDTLS
    /* Real implementation would:
     * - Parse broker_url for host/port
     * - TCP connect
     * - mbedtls_ssl_handshake with device cert
     * - Send MQTT CONNECT
     * - Receive CONNACK, extract server timestamp from user property
     * - Subscribe to verdict/resp, ota/policy, ota/firmware, cmd/request, broadcast
     */
    (void)broker_url;
    return -1; /* Not yet implemented with real TLS */
#else
    (void)broker_url;
    /* Dev mode: mark as connected for testing pipeline logic */
    mqtt_ctx.state = MQTT_STATE_CONNECTED;
    dclaw_get_state()->online = true;

    /* Generate pseudo session_id for HMAC derivation */
    hal_random_bytes(mqtt_ctx.session_id, 16);
    return 0;
#endif
}

int dclaw_mqtt_reconnect(void) {
    if (mqtt_ctx.state == MQTT_STATE_CONNECTED) return 0;

    uint32_t now = hal_tick_ms();
    if (now - mqtt_ctx.last_attempt_tick < mqtt_ctx.backoff_ms) {
        return -1; /* Too soon, backoff not elapsed */
    }

    int rc = dclaw_mqtt_connect();
    if (rc != 0) {
        /* Failed — try next broker or increase backoff */
        mqtt_ctx.broker_index++;
        if (!dclaw_config_get_broker(mqtt_ctx.broker_index)) {
            /* Exhausted broker list, reset and increase backoff */
            mqtt_ctx.broker_index = 0;
            mqtt_ctx.backoff_ms *= 2;
            if (mqtt_ctx.backoff_ms > 300000) mqtt_ctx.backoff_ms = 300000; /* 5 min max */
        }
        mqtt_ctx.state = MQTT_STATE_RECONNECTING;
    } else {
        mqtt_ctx.backoff_ms = 1000; /* Reset backoff on success */
        mqtt_ctx.broker_index = 0;
    }
    return rc;
}

int dclaw_mqtt_publish(const char *topic, const void *payload, size_t len, uint8_t qos) {
    if (mqtt_ctx.state != MQTT_STATE_CONNECTED) return -1;

    (void)topic; (void)payload; (void)len; (void)qos;

    /*
     * Phase 1 stub: in production, this would:
     * 1. Build MQTT PUBLISH packet (v5, topic, QoS, packet_id if QoS>0)
     * 2. Write to TLS socket
     * 3. If QoS 1: store in pending-ack table, wait for PUBACK
     */
    mqtt_ctx.next_packet_id++;
    return 0;
}

int dclaw_mqtt_disconnect(void) {
    mqtt_ctx.state = MQTT_STATE_DISCONNECTED;
    dclaw_get_state()->online = false;
    if (mqtt_ctx.socket_fd >= 0) {
        hal_ipc_socket_close(mqtt_ctx.socket_fd);
        mqtt_ctx.socket_fd = -1;
    }
    return 0;
}

bool dclaw_mqtt_is_connected(void) {
    return mqtt_ctx.state == MQTT_STATE_CONNECTED;
}

const char *dclaw_mqtt_get_session_id(void) {
    return mqtt_ctx.session_id;
}

/* Heartbeat publish (called from event loop) */
int dclaw_mqtt_send_heartbeat(void) {
    if (!dclaw_mqtt_is_connected()) return -1;

    uint32_t now = hal_tick_ms();
    if (now - mqtt_ctx.last_heartbeat_tick < (uint32_t)(DCLAW_HEARTBEAT_INTERVAL_SEC * 1000)) {
        return 0; /* Not time yet */
    }
    mqtt_ctx.last_heartbeat_tick = now;

    uint8_t hb_buf[32];
    size_t hb_len;
    if (dclaw_cbor_encode_heartbeat(hb_buf, &hb_len, sizeof(hb_buf)) != 0) return -1;

    char topic[128];
    if (build_topic(topic, sizeof(topic), "heartbeat") != 0) return -1;

    return dclaw_mqtt_publish(topic, hb_buf, hb_len, 0 /* QoS 0 */);
}

/* Verdict request publish */
int dclaw_mqtt_send_verdict_request(const dclaw_tool_request_t *req,
                                    uint16_t request_id) {
    if (!dclaw_mqtt_is_connected()) return -1;

    uint8_t cbor_buf[128];
    size_t cbor_len;
    if (dclaw_cbor_encode_verdict_request(req, request_id, 0,
                                          cbor_buf, &cbor_len, sizeof(cbor_buf)) != 0) {
        return -1;
    }

    char topic[128];
    if (build_topic(topic, sizeof(topic), "verdict/req") != 0) return -1;

    return dclaw_mqtt_publish(topic, cbor_buf, cbor_len, 1 /* QoS 1 */);
}
