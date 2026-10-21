/* A QoS 1 verdict request must be sent without blocking the daemon's event
 * loop on the broker's PUBACK; the PUBACK is consumed later by MQTTYield. */
#include "MQTTClient.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned char incoming[16];
static int incoming_len;
static int incoming_pos;
static int reads;
static unsigned char outgoing[128];
static int outgoing_len;

static int read_packet(Network *net, unsigned char *buf, int len, int timeout_ms) {
    (void)net;
    (void)timeout_ms;
    reads++;
    int available = incoming_len - incoming_pos;
    if (available < len) return available > 0 ? available : 0;
    memcpy(buf, incoming + incoming_pos, (size_t)len);
    incoming_pos += len;
    return len;
}

static int write_packet(Network *net, unsigned char *buf, int len, int timeout_ms) {
    (void)net;
    (void)timeout_ms;
    assert(len > 0 && (size_t)len <= sizeof(outgoing));
    memcpy(outgoing, buf, (size_t)len);
    outgoing_len = len;
    return len;
}

int main(void) {
    Network net = {.my_socket = -1, .tls_active = false,
                   .mqttread = read_packet, .mqttwrite = write_packet};
    MQTTClient client = {0};
    unsigned char sendbuf[128], readbuf[128];
    MQTTClientInit(&client, &net, 1000, sendbuf, sizeof(sendbuf),
                   readbuf, sizeof(readbuf));
    client.isconnected = 1;

    unsigned char payload[3] = {1, 2, 3};
    MQTTMessage msg = {.qos = QOS1, .retained = 0, .dup = 0,
                       .payload = payload, .payloadlen = sizeof(payload)};
    assert(MQTTPublishNoWait(&client, "defenseclaw/1/2/3/verdict/req", &msg) == SUCCESS);
    assert(reads == 0);                    /* did not wait for PUBACK */
    assert(outgoing_len > 0 && (outgoing[0] & 0xF0) == 0x30); /* PUBLISH */
    assert((outgoing[0] & 0x06) == 0x02);  /* QoS 1 */
    assert(msg.id != 0);
    assert(client.isconnected);

    /* The broker's PUBACK arrives later and is absorbed by the normal yield. */
    incoming[0] = 0x40; incoming[1] = 0x02;
    incoming[2] = (unsigned char)(msg.id >> 8); incoming[3] = (unsigned char)msg.id;
    incoming_len = 4;
    assert(MQTTYield(&client, 1) == SUCCESS);
    assert(client.isconnected);
    puts("QoS1 publish returns before PUBACK; later PUBACK absorbed by yield");
    return 0;
}
