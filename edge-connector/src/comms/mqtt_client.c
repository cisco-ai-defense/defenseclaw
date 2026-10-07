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

/* P1-24 fix: The mbedTLS HMAC path in dclaw_mqtt_send_heartbeat() uses
 * mbedtls_md_context_t, mbedtls_md_info_t, and MBEDTLS_MD_SHA256.
 * Include the header when mbedTLS is available. */
#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS == 1
#include <mbedtls/md.h>
#endif

/*
 * Minimal MQTT 3.1.1 client for Edge Connector.
 *
 * Implements CONNECT, CONNACK, PUBLISH, SUBSCRIBE, SUBACK,
 * PINGREQ, PINGRESP, and DISCONNECT using raw POSIX sockets.
 * No external MQTT library dependencies.
 *
 * Phase 1 implementation: connection state machine with broker fallback.
 * TLS/mTLS handshake uses mbedTLS (when available).
 * Without mbedTLS: operates in plaintext mode for development/testing only.
 *
 * Production deployment requires DCLAW_HAS_MBEDTLS=1.
 */

/* MQTT 3.1.1 packet types (high nibble of first byte) */
#define MQTT_PKT_CONNECT     0x10
#define MQTT_PKT_CONNACK     0x20
#define MQTT_PKT_PUBLISH     0x30
#define MQTT_PKT_PUBACK      0x40
#define MQTT_PKT_SUBSCRIBE   0x82  /* type 8, QoS 1 required for SUBSCRIBE */
#define MQTT_PKT_SUBACK      0x90
#define MQTT_PKT_PINGREQ     0xC0
#define MQTT_PKT_PINGRESP    0xD0
#define MQTT_PKT_DISCONNECT  0xE0

#define MQTT_DEFAULT_PORT    1883
#define MQTT_KEEPALIVE_SEC   60
#define MQTT_RECV_BUF_SIZE   512

typedef enum {
    MQTT_STATE_DISCONNECTED,
    MQTT_STATE_CONNECTING,
    MQTT_STATE_CONNECTED,
    MQTT_STATE_RECONNECTING,
} mqtt_state_t;

typedef struct {
    mqtt_state_t state;
    uint8_t      broker_index;
    uint64_t     backoff_ms;
    uint64_t     last_attempt_tick;
    uint64_t     last_heartbeat_tick;
    uint64_t     last_activity_tick;  /* for keepalive tracking */
    uint16_t     next_packet_id;
    int          socket_fd;
    char         session_id[32];
    uint8_t      recv_buf[MQTT_RECV_BUF_SIZE];
    size_t       recv_len;
} mqtt_context_t;

static mqtt_context_t mqtt_ctx;

/*
 * Pending request tracking table — ring-buffer of {request_id, tool_hash} pairs.
 * When a verdict request is sent, the tool hash is stored here so that
 * the HMAC verifier can look it up when the response arrives.
 */
#define MQTT_PENDING_RING_SIZE  16

typedef struct {
    uint16_t request_id;
    uint8_t  tool_hash[32];
    bool     occupied;
} mqtt_pending_entry_t;

static mqtt_pending_entry_t pending_ring[MQTT_PENDING_RING_SIZE];
static uint8_t pending_ring_next = 0;

void dclaw_mqtt_pending_store(uint16_t request_id, const uint8_t *tool_hash) {
    mqtt_pending_entry_t *slot = &pending_ring[pending_ring_next];
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

/* === MQTT packet encoding helpers === */

/*
 * Encode MQTT remaining length (variable-length encoding, 1-4 bytes).
 * Returns number of bytes written to buf.
 */
static int mqtt_encode_remaining_length(uint8_t *buf, uint32_t length) {
    int i = 0;
    do {
        uint8_t byte = (uint8_t)(length & 0x7F);
        length >>= 7;
        if (length > 0) byte |= 0x80;
        buf[i++] = byte;
    } while (length > 0 && i < 4);
    return i;
}

/*
 * Decode MQTT remaining length from a buffer.
 * Returns the decoded length, sets *bytes_consumed to the number of
 * bytes read from buf. Returns -1 on malformed encoding.
 */
static int32_t mqtt_decode_remaining_length(const uint8_t *buf, size_t available,
                                            int *bytes_consumed) {
    uint32_t value = 0;
    uint32_t multiplier = 1;
    int i = 0;
    do {
        if ((size_t)i >= available) return -1;
        uint8_t byte = buf[i];
        value += (uint32_t)(byte & 0x7F) * multiplier;
        multiplier *= 128;
        i++;
        if (!(byte & 0x80)) break;
    } while (i < 4);
    *bytes_consumed = i;
    return (int32_t)value;
}

/*
 * Write a UTF-8 encoded string (2-byte length prefix + data) per MQTT spec.
 * Returns number of bytes written.
 */
static int mqtt_write_utf8_string(uint8_t *buf, const char *str, uint16_t len) {
    buf[0] = (uint8_t)(len >> 8);
    buf[1] = (uint8_t)(len & 0xFF);
    memcpy(buf + 2, str, len);
    return 2 + len;
}

/* === TCP socket helpers === */

/*
 * Parse broker URL: extract host and port.
 * Supported formats: mqtt://host:port, mqtts://host:port, host:port
 * Returns 0 on success.
 */
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

    /* Find colon separator for port */
    const char *colon = strchr(p, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - p);
        if (hlen >= host_size) return -1;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        *port = (uint16_t)strtoul(colon + 1, NULL, 10);
    } else {
        size_t hlen = strlen(p);
        if (hlen >= host_size) return -1;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        *port = *is_tls ? 8883 : MQTT_DEFAULT_PORT;
    }
    return 0;
}

/*
 * Create a TCP connection to host:port.
 * Returns socket fd on success, -1 on failure.
 */
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

        /* Set non-blocking before connect to enforce a timeout */
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }

        rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) {
            break; /* connected immediately */
        }
        if (errno == EINPROGRESS) {
            /* Wait up to 5 seconds for the connection to complete */
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            int poll_rc = poll(&pfd, 1, 5000);
            if (poll_rc > 0 && (pfd.revents & POLLOUT)) {
                int sock_err = 0;
                socklen_t errlen = sizeof(sock_err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &errlen);
                if (sock_err == 0) {
                    break; /* success */
                }
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

    /* Ensure non-blocking is set (already set above, but be explicit) */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    return fd;
}

/*
 * Blocking write with retry on EINTR. Assumes socket is non-blocking
 * but we just connected, so kernel buffer should be empty.
 * Returns 0 on success, -1 on error.
 */
static int sock_write_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Brief poll to wait for writability */
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                poll(&pfd, 1, 100);
                continue;
            }
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

/*
 * Blocking read with timeout. Returns bytes read, or -1 on error/timeout.
 */
static ssize_t sock_read_timeout(int fd, uint8_t *buf, size_t len, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return -1;
    ssize_t n = read(fd, buf, len);
    return n;
}

/* === MQTT protocol operations === */

/*
 * Build and send MQTT CONNECT packet (v3.1.1).
 * Clean session, keepalive = MQTT_KEEPALIVE_SEC.
 * Client ID = "dclaw-{device_id}".
 *
 * P0-4 fix: If DCLAW_MQTT_USER and DCLAW_MQTT_PASS are set in the environment,
 * include username/password in the CONNECT packet so authenticated brokers
 * (set up by `defenseclaw setup mqtt-broker`) accept the connection.
 */
static int mqtt_send_connect(int fd) {
    dclaw_state_t *s = dclaw_get_state();
    char client_id[32];
    int cid_len = snprintf(client_id, sizeof(client_id), "dclaw-%u", s->device.device_id);
    if (cid_len <= 0 || (size_t)cid_len >= sizeof(client_id)) return -1;

    /* Read optional MQTT credentials from environment */
    const char *mqtt_user = getenv("DCLAW_MQTT_USER");
    const char *mqtt_pass = getenv("DCLAW_MQTT_PASS");
    uint16_t user_len = (mqtt_user && mqtt_user[0]) ? (uint16_t)strlen(mqtt_user) : 0;
    uint16_t pass_len = (mqtt_pass && mqtt_pass[0]) ? (uint16_t)strlen(mqtt_pass) : 0;

    /*
     * Variable header (10 bytes):
     *   Protocol Name: 0x00 0x04 "MQTT"
     *   Protocol Level: 0x04 (v3.1.1)
     *   Connect Flags: 0x02 (clean session) | username/password bits
     *   Keep Alive: MQTT_KEEPALIVE_SEC
     *
     * Payload: client_id (UTF-8 string) [+ username] [+ password]
     */
    uint8_t connect_flags = 0x02; /* clean session */
    if (user_len > 0) connect_flags |= 0x80; /* bit 7: username flag */
    if (pass_len > 0) connect_flags |= 0x40; /* bit 6: password flag */

    uint16_t client_id_len = (uint16_t)cid_len;
    uint32_t remaining = 10 + 2 + client_id_len;
    if (user_len > 0) remaining += 2 + user_len;
    if (pass_len > 0) remaining += 2 + pass_len;

    /* P1-04 fix: Reject if the packet would overflow the fixed buffer.
     * The fixed header is at most 5 bytes (1 type + 4 remaining-length). */
    uint8_t pkt[512];
    if (1 + 4 + remaining > sizeof(pkt)) {
        fprintf(stderr, "[DCLAW-MQTT] CONNECT packet too large (%u bytes) — "
                "check DCLAW_MQTT_USER/DCLAW_MQTT_PASS length\n",
                (unsigned)(1 + 4 + remaining));
        return -1;
    }
    int pos = 0;

    /* Fixed header */
    pkt[pos++] = MQTT_PKT_CONNECT;
    pos += mqtt_encode_remaining_length(pkt + pos, remaining);

    /* Variable header */
    pkt[pos++] = 0x00; pkt[pos++] = 0x04; /* Protocol Name Length */
    pkt[pos++] = 'M'; pkt[pos++] = 'Q'; pkt[pos++] = 'T'; pkt[pos++] = 'T';
    pkt[pos++] = 0x04; /* Protocol Level: 3.1.1 */
    pkt[pos++] = connect_flags;
    pkt[pos++] = (uint8_t)(MQTT_KEEPALIVE_SEC >> 8);
    pkt[pos++] = (uint8_t)(MQTT_KEEPALIVE_SEC & 0xFF);

    /* Payload: Client ID */
    pos += mqtt_write_utf8_string(pkt + pos, client_id, client_id_len);

    /* Payload: Username (if set) */
    if (user_len > 0) {
        pos += mqtt_write_utf8_string(pkt + pos, mqtt_user, user_len);
    }

    /* Payload: Password (if set) */
    if (pass_len > 0) {
        pos += mqtt_write_utf8_string(pkt + pos, mqtt_pass, pass_len);
    }

    return sock_write_all(fd, pkt, (size_t)pos);
}

/*
 * Read and validate CONNACK response.
 * Returns 0 on success (connection accepted), -1 on failure.
 */
static int mqtt_read_connack(int fd) {
    uint8_t buf[4];
    ssize_t n = sock_read_timeout(fd, buf, sizeof(buf), 5000);
    if (n < 4) {
        fprintf(stderr, "[DCLAW-MQTT] CONNACK too short or timeout (got %zd bytes)\n", n);
        return -1;
    }

    /* Verify: packet type 0x20, remaining length 0x02, return code 0x00 */
    if ((buf[0] & 0xF0) != MQTT_PKT_CONNACK) {
        fprintf(stderr, "[DCLAW-MQTT] Expected CONNACK, got 0x%02x\n", buf[0]);
        return -1;
    }
    if (buf[1] != 0x02) {
        fprintf(stderr, "[DCLAW-MQTT] Bad CONNACK remaining length: %u\n", buf[1]);
        return -1;
    }
    /* buf[2] = session present flag (ignored) */
    if (buf[3] != 0x00) {
        fprintf(stderr, "[DCLAW-MQTT] CONNACK return code: %u (rejected)\n", buf[3]);
        return -1;
    }

    return 0;
}

/*
 * Build and send MQTT SUBSCRIBE packet for a single topic.
 */
static int mqtt_send_subscribe(int fd, const char *topic, uint8_t qos,
                               uint16_t packet_id) {
    uint16_t topic_len = (uint16_t)strlen(topic);
    uint32_t remaining = 2 + 2 + topic_len + 1; /* packet_id + topic + qos */

    uint8_t pkt[256];
    int pos = 0;

    /* Fixed header: type 8, reserved bits = 0x02 (required by spec) */
    pkt[pos++] = MQTT_PKT_SUBSCRIBE;
    pos += mqtt_encode_remaining_length(pkt + pos, remaining);

    /* Variable header: packet identifier */
    pkt[pos++] = (uint8_t)(packet_id >> 8);
    pkt[pos++] = (uint8_t)(packet_id & 0xFF);

    /* Payload: topic filter + requested QoS */
    pos += mqtt_write_utf8_string(pkt + pos, topic, topic_len);
    pkt[pos++] = qos;

    return sock_write_all(fd, pkt, (size_t)pos);
}

/*
 * Read SUBACK response. Returns 0 on success.
 */
static int mqtt_read_suback(int fd) {
    uint8_t buf[8];
    ssize_t n = sock_read_timeout(fd, buf, sizeof(buf), 5000);
    if (n < 5) return -1;

    if ((buf[0] & 0xF0) != MQTT_PKT_SUBACK) {
        fprintf(stderr, "[DCLAW-MQTT] Expected SUBACK, got 0x%02x\n", buf[0]);
        return -1;
    }

    /* buf[4] = granted QoS (0x80 means failure) */
    if (buf[4] == 0x80) {
        fprintf(stderr, "[DCLAW-MQTT] SUBSCRIBE rejected by broker\n");
        return -1;
    }

    return 0;
}

/*
 * Subscribe to the standard DefenseClaw device topics.
 */
static int mqtt_subscribe_topics(int fd) {
    dclaw_state_t *s = dclaw_get_state();
    char topic[128];

    /* Subscribe to verdict responses */
    snprintf(topic, sizeof(topic), "defenseclaw/%u/%u/%u/verdict/resp",
             s->device.tenant_id, s->device.fleet_id, s->device.device_id);
    if (mqtt_send_subscribe(fd, topic, 1, mqtt_ctx.next_packet_id++) != 0) return -1;
    if (mqtt_read_suback(fd) != 0) return -1;

    /* Subscribe to OTA policy updates (fleet-wide) */
    snprintf(topic, sizeof(topic), "defenseclaw/%u/%u/ota/policy",
             s->device.tenant_id, s->device.fleet_id);
    if (mqtt_send_subscribe(fd, topic, 1, mqtt_ctx.next_packet_id++) != 0) return -1;
    if (mqtt_read_suback(fd) != 0) return -1;

    /* Subscribe to emergency broadcasts (fleet-wide) */
    snprintf(topic, sizeof(topic), "defenseclaw/%u/%u/ota/emergency",
             s->device.tenant_id, s->device.fleet_id);
    if (mqtt_send_subscribe(fd, topic, 1, mqtt_ctx.next_packet_id++) != 0) return -1;
    if (mqtt_read_suback(fd) != 0) return -1;

    return 0;
}

/*
 * Send MQTT PINGREQ (2 bytes: 0xC0, 0x00).
 */
static int mqtt_send_pingreq(int fd) {
    uint8_t pkt[2] = { MQTT_PKT_PINGREQ, 0x00 };
    return sock_write_all(fd, pkt, 2);
}

/*
 * Send MQTT DISCONNECT (2 bytes: 0xE0, 0x00) and close socket.
 */
static void mqtt_send_disconnect(int fd) {
    uint8_t pkt[2] = { MQTT_PKT_DISCONNECT, 0x00 };
    sock_write_all(fd, pkt, 2); /* best-effort */
}

/*
 * Mark connection as lost. Closes socket and sets state for reconnect.
 */
static void mqtt_mark_disconnected(void) {
    if (mqtt_ctx.socket_fd >= 0) {
        close(mqtt_ctx.socket_fd);
        mqtt_ctx.socket_fd = -1;
    }
    mqtt_ctx.state = MQTT_STATE_DISCONNECTED;
    dclaw_get_state()->online = false;
    mqtt_ctx.recv_len = 0;
}

/* Topic construction helper */
static int build_topic(char *buf, size_t buf_size, const char *suffix) {
    dclaw_state_t *s = dclaw_get_state();
    int n = snprintf(buf, buf_size, "defenseclaw/%u/%u/%u/%s",
                     s->device.tenant_id, s->device.fleet_id,
                     s->device.device_id, suffix);
    return (n > 0 && (size_t)n < buf_size) ? 0 : -1;
}

/*
 * Route an incoming PUBLISH message by topic suffix.
 */
static void mqtt_route_publish(const char *topic, const uint8_t *payload,
                               size_t payload_len) {
    /* Check for verdict/resp suffix */
    const char *suffix = strstr(topic, "verdict/resp");
    if (suffix) {
        /*
         * Extract request_id from the response payload (first 2 bytes, big-endian)
         * to look up the original tool hash for HMAC verification.
         */
        if (payload_len >= 2) {
            uint16_t request_id = (uint16_t)((payload[0] << 8) | payload[1]);
            const uint8_t *tool_hash = dclaw_mqtt_pending_lookup(request_id);
            if (tool_hash) {
                dclaw_verdict_handle_response(payload, payload_len, tool_hash);
            } else {
                /* Unknown request_id — no matching pending request, drop the response */
                fprintf(stderr, "[DCLAW-MQTT] Verdict response for unknown request_id %u\n",
                        request_id);
            }
        }
        return;
    }

    suffix = strstr(topic, "ota/policy");
    if (suffix) {
        /* Policy blob format: payload = blob + 64-byte Ed25519 signature appended */
        if (payload_len > 64) {
            uint32_t blob_len = (uint32_t)(payload_len - 64);
            const uint8_t *signature = payload + blob_len;
            dclaw_apply_policy(payload, blob_len, signature);
        }
        return;
    }

    suffix = strstr(topic, "ota/emergency");
    if (suffix) {
        dclaw_apply_emergency(payload, (uint32_t)payload_len);
        return;
    }

    /* Unknown topic — ignore */
}

/*
 * Process a single complete MQTT packet from the receive buffer.
 * Returns the total packet length consumed, or -1 on error.
 */
static int mqtt_process_packet(const uint8_t *buf, size_t available) {
    if (available < 2) return 0; /* need more data */

    uint8_t pkt_type = buf[0] & 0xF0;
    int rl_consumed;
    int32_t remaining = mqtt_decode_remaining_length(buf + 1, available - 1,
                                                     &rl_consumed);
    if (remaining < 0) return 0; /* incomplete length encoding */

    size_t total_len = 1 + (size_t)rl_consumed + (size_t)remaining;
    if (available < total_len) return 0; /* incomplete packet */

    const uint8_t *var_hdr = buf + 1 + rl_consumed;

    switch (pkt_type) {
    case MQTT_PKT_PUBLISH: {
        /* Parse PUBLISH: topic length + topic + [packet_id] + payload */
        if (remaining < 2) break;
        uint16_t topic_len = (uint16_t)((var_hdr[0] << 8) | var_hdr[1]);
        if ((int32_t)(2 + topic_len) > remaining) break;

        char topic[128];
        size_t copy_len = (topic_len < sizeof(topic) - 1) ? topic_len : sizeof(topic) - 1;
        memcpy(topic, var_hdr + 2, copy_len);
        topic[copy_len] = '\0';

        uint8_t qos = (buf[0] >> 1) & 0x03;
        size_t offset = 2 + topic_len;

        /* QoS > 0 has a 2-byte packet identifier */
        uint16_t pkt_id = 0;
        if (qos > 0) {
            if ((int32_t)(offset + 2) > remaining) break;
            pkt_id = (uint16_t)((var_hdr[offset] << 8) | var_hdr[offset + 1]);
            offset += 2;

            /* Send PUBACK for QoS 1 */
            if (qos == 1) {
                uint8_t puback[4] = {
                    MQTT_PKT_PUBACK, 0x02,
                    (uint8_t)(pkt_id >> 8), (uint8_t)(pkt_id & 0xFF)
                };
                sock_write_all(mqtt_ctx.socket_fd, puback, 4);
            }
        }

        size_t payload_len = (size_t)remaining - offset;
        const uint8_t *payload = var_hdr + offset;
        mqtt_route_publish(topic, payload, payload_len);
        break;
    }

    case MQTT_PKT_PUBACK:
        /* QoS 1 acknowledgment — fire-and-forget, nothing to do */
        break;

    case MQTT_PKT_SUBACK:
        /* Late SUBACK — already handled during connect phase */
        break;

    case MQTT_PKT_PINGRESP:
        /* Keepalive response received — connection is alive */
        break;

    default:
        /* Unknown packet type — skip */
        break;
    }

    return (int)total_len;
}

/* === Public API === */

/* Forward declaration — dclaw_mqtt_publish is defined below dclaw_mqtt_connect
 * but is called during connection setup to send the registration message. */
int dclaw_mqtt_publish(const char *topic, const void *payload, size_t len, uint8_t qos);

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

#if DCLAW_HAS_MBEDTLS
    /* Comment 35 fix: mbedTLS TLS/mTLS MQTT path is not yet implemented.
     * The -1 return is intentional — callers will fall through to the
     * reconnect/backoff logic. For development and testing, build without
     * DCLAW_HAS_MBEDTLS and use plaintext MQTT (mqtt:// URLs).
     *
     * TODO(Phase 2): Implement TLS handshake with mbedtls_ssl:
     *   - Parse broker_url for host/port
     *   - TCP connect
     *   - mbedtls_ssl_handshake with device cert (mTLS)
     *   - Send MQTT CONNECT over the TLS session
     *   - Receive CONNACK, extract server timestamp
     *   - Subscribe to verdict/resp, ota/policy, ota/emergency
     */
    (void)broker_url;
    fprintf(stderr, "[DCLAW-MQTT] ERROR: TLS MQTT connection not yet implemented. "
            "Build without DCLAW_HAS_MBEDTLS=1 and use mqtt:// URLs for "
            "development/testing, or wait for Phase 2 TLS support.\n");
    mqtt_ctx.state = MQTT_STATE_DISCONNECTED;
    return -1;
#else
    /* Dev mode: real TCP + MQTT 3.1.1, but no TLS */
    char host[128];
    uint16_t port;
    bool is_tls;

    if (parse_broker_url(broker_url, host, sizeof(host), &port, &is_tls) != 0) {
        fprintf(stderr, "[DCLAW-MQTT] Bad broker URL: %s\n", broker_url);
        mqtt_ctx.state = MQTT_STATE_DISCONNECTED;
        return -1;
    }

    if (is_tls) {
        fprintf(stderr, "[DCLAW-MQTT] ERROR: mqtts:// requested but mbedTLS not available. "
                "Refusing to connect over plain TCP. Build with DCLAW_HAS_MBEDTLS=1 "
                "or use mqtt:// for development only.\n");
        mqtt_ctx.state = MQTT_STATE_DISCONNECTED;
        return -1;
    }

    /* Step 1: TCP connect */
    int fd = tcp_connect(host, port);
    if (fd < 0) {
        mqtt_ctx.state = MQTT_STATE_DISCONNECTED;
        return -1;
    }

    /* Temporarily make socket blocking for the handshake sequence */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }

    /* Step 2: Send MQTT CONNECT */
    if (mqtt_send_connect(fd) != 0) {
        fprintf(stderr, "[DCLAW-MQTT] Failed to send CONNECT packet\n");
        close(fd);
        mqtt_ctx.state = MQTT_STATE_DISCONNECTED;
        return -1;
    }

    /* Step 3: Read CONNACK */
    if (mqtt_read_connack(fd) != 0) {
        fprintf(stderr, "[DCLAW-MQTT] CONNACK handshake failed\n");
        close(fd);
        mqtt_ctx.state = MQTT_STATE_DISCONNECTED;
        return -1;
    }

    /* Step 4: Subscribe to device topics */
    mqtt_ctx.socket_fd = fd;  /* needed by subscribe for packet_id tracking */
    if (mqtt_subscribe_topics(fd) != 0) {
        fprintf(stderr, "[DCLAW-MQTT] Subscribe failed\n");
        close(fd);
        mqtt_ctx.socket_fd = -1;
        mqtt_ctx.state = MQTT_STATE_DISCONNECTED;
        return -1;
    }

    /* Set socket back to non-blocking for the event loop */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    mqtt_ctx.state = MQTT_STATE_CONNECTED;
    mqtt_ctx.last_activity_tick = hal_tick_ms();
    mqtt_ctx.recv_len = 0;
    dclaw_get_state()->online = true;

    /* Use device ID as decimal string for session_id (Comment 32 fix).
     * This must match the Go side (bridge.go) which uses
     * fmt.Sprintf("%d", parts.DeviceID) for the HMAC session_id input. */
    snprintf(mqtt_ctx.session_id, sizeof(mqtt_ctx.session_id), "%u",
             dclaw_get_state()->device.device_id);

    /* Step 5: Publish registration message so the fleet manager knows about
     * this device immediately, without waiting for the first heartbeat.
     * Uses the same 32-byte heartbeat wire format (device_id, fw_version,
     * policy_version, capabilities, etc.) as the registration payload.
     * QoS 1 ensures at-least-once delivery. */
    {
        uint8_t reg_buf[32];
        size_t reg_len;
        if (dclaw_cbor_encode_heartbeat(reg_buf, &reg_len, sizeof(reg_buf)) == 0) {
            char reg_topic[128];
            if (build_topic(reg_topic, sizeof(reg_topic), "register") == 0) {
                if (dclaw_mqtt_publish(reg_topic, reg_buf, reg_len, 1 /* QoS 1 */) != 0) {
                    fprintf(stderr, "[DCLAW-MQTT] Failed to publish registration message\n");
                } else {
                    fprintf(stderr, "[DCLAW-MQTT] Registration message sent on %s\n", reg_topic);
                }
            }
        }
    }

    fprintf(stderr, "[DCLAW-MQTT] Connected to %s:%u\n", host, port);
    return 0;
#endif
}

int dclaw_mqtt_reconnect(void) {
    if (mqtt_ctx.state == MQTT_STATE_CONNECTED) return 0;

    uint64_t now = hal_tick_ms();
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
    if (mqtt_ctx.socket_fd < 0) return -1;

    uint16_t topic_len = (uint16_t)strlen(topic);
    uint32_t remaining = 2 + topic_len + (uint32_t)len;
    uint16_t packet_id = 0;

    if (qos > 0) {
        packet_id = mqtt_ctx.next_packet_id++;
        remaining += 2; /* packet identifier */
    }

    /*
     * Build PUBLISH packet:
     *   Fixed header: type 3, DUP=0, QoS, RETAIN=0
     *   + remaining length (variable)
     *   + topic (UTF-8 string)
     *   + packet_id (if QoS > 0)
     *   + payload
     */
    uint8_t hdr[8];
    int pos = 0;
    hdr[pos++] = (uint8_t)(MQTT_PKT_PUBLISH | ((qos & 0x03) << 1));
    pos += mqtt_encode_remaining_length(hdr + pos, remaining);

    /* Write fixed header */
    if (sock_write_all(mqtt_ctx.socket_fd, hdr, (size_t)pos) != 0) {
        mqtt_mark_disconnected();
        return -1;
    }

    /* Write topic (UTF-8 string: 2-byte length + data) */
    uint8_t topic_hdr[2] = {
        (uint8_t)(topic_len >> 8), (uint8_t)(topic_len & 0xFF)
    };
    if (sock_write_all(mqtt_ctx.socket_fd, topic_hdr, 2) != 0) {
        mqtt_mark_disconnected();
        return -1;
    }
    if (sock_write_all(mqtt_ctx.socket_fd, (const uint8_t *)topic, topic_len) != 0) {
        mqtt_mark_disconnected();
        return -1;
    }

    /* Write packet ID for QoS > 0 */
    if (qos > 0) {
        uint8_t pid[2] = {
            (uint8_t)(packet_id >> 8), (uint8_t)(packet_id & 0xFF)
        };
        if (sock_write_all(mqtt_ctx.socket_fd, pid, 2) != 0) {
            mqtt_mark_disconnected();
            return -1;
        }
    }

    /* Write payload */
    if (len > 0) {
        if (sock_write_all(mqtt_ctx.socket_fd, (const uint8_t *)payload, len) != 0) {
            mqtt_mark_disconnected();
            return -1;
        }
    }

    mqtt_ctx.last_activity_tick = hal_tick_ms();
    return 0;
}

int dclaw_mqtt_subscribe(const char *topic, uint8_t qos) {
    if (mqtt_ctx.state != MQTT_STATE_CONNECTED) return -1;
    if (mqtt_ctx.socket_fd < 0) return -1;

    uint16_t pkt_id = mqtt_ctx.next_packet_id++;
    return mqtt_send_subscribe(mqtt_ctx.socket_fd, topic, qos, pkt_id);
    /* Note: SUBACK will be consumed by dclaw_mqtt_poll() */
}

int dclaw_mqtt_poll(int timeout_ms) {
    if (mqtt_ctx.state != MQTT_STATE_CONNECTED) return -1;
    if (mqtt_ctx.socket_fd < 0) return -1;

    /* Non-blocking recv into buffer */
    struct pollfd pfd = { .fd = mqtt_ctx.socket_fd, .events = POLLIN };
    int rc = poll(&pfd, 1, timeout_ms);

    if (rc < 0) {
        if (errno == EINTR) return 0;
        mqtt_mark_disconnected();
        return -1;
    }

    if (rc > 0 && (pfd.revents & POLLIN)) {
        size_t space = MQTT_RECV_BUF_SIZE - mqtt_ctx.recv_len;
        if (space == 0) {
            /* Buffer full, shouldn't happen — reset */
            mqtt_ctx.recv_len = 0;
            space = MQTT_RECV_BUF_SIZE;
        }

        ssize_t n = read(mqtt_ctx.socket_fd, mqtt_ctx.recv_buf + mqtt_ctx.recv_len, space);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* Spurious wakeup, no data */
        } else if (n <= 0) {
            /* Connection closed or error */
            fprintf(stderr, "[DCLAW-MQTT] Connection lost (read returned %zd)\n", n);
            mqtt_mark_disconnected();
            return -1;
        } else {
            mqtt_ctx.recv_len += (size_t)n;
            mqtt_ctx.last_activity_tick = hal_tick_ms();
        }
    }

    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        fprintf(stderr, "[DCLAW-MQTT] Socket error (revents=0x%x)\n", pfd.revents);
        mqtt_mark_disconnected();
        return -1;
    }

    /* Process all complete packets in the receive buffer */
    while (mqtt_ctx.recv_len > 0) {
        int consumed = mqtt_process_packet(mqtt_ctx.recv_buf, mqtt_ctx.recv_len);
        if (consumed <= 0) break; /* incomplete packet, wait for more data */

        /* Shift remaining data to front of buffer */
        mqtt_ctx.recv_len -= (size_t)consumed;
        if (mqtt_ctx.recv_len > 0) {
            memmove(mqtt_ctx.recv_buf, mqtt_ctx.recv_buf + consumed, mqtt_ctx.recv_len);
        }
    }

    /* Keepalive: send PINGREQ if no activity for keepalive interval */
    uint64_t now = hal_tick_ms();
    if (now - mqtt_ctx.last_activity_tick >= (uint64_t)(MQTT_KEEPALIVE_SEC * 1000)) {
        if (mqtt_send_pingreq(mqtt_ctx.socket_fd) != 0) {
            mqtt_mark_disconnected();
            return -1;
        }
        mqtt_ctx.last_activity_tick = now;
    }

    return 0;
}

int dclaw_mqtt_disconnect(void) {
    if (mqtt_ctx.socket_fd >= 0) {
        mqtt_send_disconnect(mqtt_ctx.socket_fd);
        close(mqtt_ctx.socket_fd);
        mqtt_ctx.socket_fd = -1;
    }
    mqtt_ctx.state = MQTT_STATE_DISCONNECTED;
    mqtt_ctx.recv_len = 0;
    dclaw_get_state()->online = false;
    return 0;
}

bool dclaw_mqtt_is_connected(void) {
    return mqtt_ctx.state == MQTT_STATE_CONNECTED;
}

const char *dclaw_mqtt_get_session_id(void) {
    return mqtt_ctx.session_id;
}

/* Forward declarations for device key access (defined in verdict_protocol.c) */
extern const uint8_t *dclaw_verdict_get_device_key(size_t *out_key_len);
extern bool dclaw_verdict_is_key_provisioned(void);

/* Heartbeat publish (called from event loop).
 *
 * P1-06 fix: When a per-device key is provisioned, append an HMAC-SHA256 tag
 * over the 32-byte heartbeat payload, making the total MQTT payload 64 bytes.
 * The fleet manager (bridge.go) verifies this tag to reject spoofed heartbeats
 * from anonymous MQTT publishers that match topic and payload device_id.
 *
 * When no key is provisioned (dev mode / zero-key fallback), the legacy 32-byte
 * unsigned format is sent for backward compatibility.
 */
int dclaw_mqtt_send_heartbeat(void) {
    if (!dclaw_mqtt_is_connected()) return -1;

    uint64_t now = hal_tick_ms();
    if (now - mqtt_ctx.last_heartbeat_tick < (uint64_t)(DCLAW_HEARTBEAT_INTERVAL_SEC * 1000)) {
        return 0; /* Not time yet */
    }
    mqtt_ctx.last_heartbeat_tick = now;

    uint8_t hb_buf[64]; /* 32 payload + 32 HMAC (if signed) */
    size_t hb_len;
    if (dclaw_cbor_encode_heartbeat(hb_buf, &hb_len, sizeof(hb_buf)) != 0) return -1;

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
            mbedtls_md_hmac_update(&ctx, hb_buf, 32);
            mbedtls_md_hmac_finish(&ctx, hmac_tag);
            mbedtls_md_free(&ctx);
#else
            dclaw_hmac_sha256(device_key, key_len, hb_buf, 32, hmac_tag);
#endif
            memcpy(hb_buf + 32, hmac_tag, 32);
            hb_len = 64;
        }
    }

    char topic[128];
    if (build_topic(topic, sizeof(topic), "heartbeat") != 0) return -1;

    return dclaw_mqtt_publish(topic, hb_buf, hb_len, 0 /* QoS 0 */);
}

/* Verdict request publish */
int dclaw_mqtt_send_verdict_request(const dclaw_tool_request_t *req,
                                    uint16_t request_id) {
    if (!dclaw_mqtt_is_connected()) return -1;

    uint8_t cbor_buf[512];
    size_t cbor_len;
    if (dclaw_cbor_encode_verdict_request(req, request_id, 0,
                                          cbor_buf, &cbor_len, sizeof(cbor_buf)) != 0) {
        return -1;
    }

    char topic[128];
    if (build_topic(topic, sizeof(topic), "verdict/req") != 0) return -1;

    return dclaw_mqtt_publish(topic, cbor_buf, cbor_len, 1 /* QoS 1 */);
}
