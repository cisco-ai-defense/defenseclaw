/* A slow OTA callback must not consume the MQTT QoS 1 PUBACK send deadline. */
#include "MQTTClient.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static unsigned char incoming[256];
static int incoming_len;
static int incoming_pos;
static unsigned char outgoing[16];
static int outgoing_len;
static int callbacks;

static int read_packet(Network *net, unsigned char *buf, int len, int timeout_ms) {
    (void)net;
    (void)timeout_ms;
    int available = incoming_len - incoming_pos;
    if (available < len) return available;
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

static void apply_slow_policy(MessageData *data) {
    assert(data->message->payloadlen == 1);
    assert(((unsigned char *)data->message->payload)[0] == 7);
    callbacks++;
    const struct timespec delay = {.tv_nsec = 30000000};
    nanosleep(&delay, NULL); /* longer than the receive poll's 10 ms */
}

int main(void) {
    MQTTString topic = MQTTString_initializer;
    topic.cstring = "ota/policy";
    unsigned char payload = 7;
    incoming_len = MQTTSerialize_publish(incoming, (int)sizeof(incoming),
                                         0, QOS1, 0, 42, topic, &payload, 1);
    assert(incoming_len > 0);

    Network net = {.my_socket = -1, .tls_active = false,
                   .mqttread = read_packet, .mqttwrite = write_packet};
    MQTTClient client;
    unsigned char sendbuf[64], readbuf[256];
    MQTTClientInit(&client, &net, 1000, sendbuf, sizeof(sendbuf),
                   readbuf, sizeof(readbuf));
    client.isconnected = 1;
    client.messageHandlers[0].topicFilter = "ota/policy";
    client.messageHandlers[0].fp = apply_slow_policy;

    assert(MQTTYield(&client, 10) == SUCCESS);
    assert(callbacks == 1 && client.isconnected);
    assert(outgoing_len == 4);
    assert(outgoing[0] == 0x40 && outgoing[1] == 0x02);
    assert(outgoing[2] == 0 && outgoing[3] == 42);
    puts("slow callback: QoS1 PUBACK sent without reconnect");
    return 0;
}
