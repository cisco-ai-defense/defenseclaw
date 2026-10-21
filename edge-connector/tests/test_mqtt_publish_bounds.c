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

/* A QoS>0 PUBLISH whose topic consumes the whole remaining length has no
 * room for the packet id. The deserializer used to read the id past the
 * packet and report a payload length of -2, which cycle() then stored in a
 * size_t as ~4 GiB and handed to the message handler. */
#include "MQTTClient.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 32 20 00 1e "defenseclaw/1/1/1/verdict/resp": QoS 1, remaining length 32,
 * 30-byte topic, no packet id. */
static const unsigned char k_no_packet_id[] = {
    0x32, 0x20, 0x00, 0x1e,
    'd','e','f','e','n','s','e','c','l','a','w','/','1','/','1','/','1','/',
    'v','e','r','d','i','c','t','/','r','e','s','p',
};

static void test_deserialize_rejects_missing_packet_id(void) {
    /* Exact-size heap copy: an over-read is reported by ASan builds. */
    unsigned char *buf = malloc(sizeof(k_no_packet_id));
    assert(buf);
    memcpy(buf, k_no_packet_id, sizeof(k_no_packet_id));
    unsigned char dup = 0, retained = 0;
    int qos = 0, payloadlen = 12345;
    unsigned short id = 0;
    MQTTString topic = MQTTString_initializer;
    unsigned char *payload = NULL;
    int rc = MQTTDeserialize_publish(&dup, &qos, &retained, &id, &topic, &payload,
                                     &payloadlen, buf, (int)sizeof(k_no_packet_id));
    assert(rc != 1);
    free(buf);
    (void)rc;

    /* The same topic with a packet id and an empty payload is valid. */
    unsigned char ok[sizeof(k_no_packet_id) + 2];
    memcpy(ok, k_no_packet_id, sizeof(k_no_packet_id));
    ok[1] = 0x22;
    ok[sizeof(k_no_packet_id)] = 0x00;
    ok[sizeof(k_no_packet_id) + 1] = 0x07;
    rc = MQTTDeserialize_publish(&dup, &qos, &retained, &id, &topic, &payload,
                                 &payloadlen, ok, (int)sizeof(ok));
    assert(rc == 1 && qos == 1 && id == 7 && payloadlen == 0);
    puts("  PASS: QoS1 PUBLISH without packet id is rejected");
}

static unsigned char incoming[64];
static int incoming_len, incoming_pos;
static int callbacks;

static int read_packet(Network *net, unsigned char *buf, int len, int timeout_ms) {
    (void)net; (void)timeout_ms;
    int available = incoming_len - incoming_pos;
    if (available < len) return available;
    memcpy(buf, incoming + incoming_pos, (size_t)len);
    incoming_pos += len;
    return len;
}

static int write_packet(Network *net, unsigned char *buf, int len, int timeout_ms) {
    (void)net; (void)buf; (void)timeout_ms;
    return len;
}

static void on_message(MessageData *data) {
    (void)data;
    callbacks++;
}

static void test_cycle_does_not_deliver_malformed_publish(void) {
    memcpy(incoming, k_no_packet_id, sizeof(k_no_packet_id));
    incoming_len = (int)sizeof(k_no_packet_id);
    incoming_pos = 0;
    Network net = {.my_socket = -1, .tls_active = false,
                   .mqttread = read_packet, .mqttwrite = write_packet};
    MQTTClient client = {0};
    unsigned char sendbuf[64], readbuf[sizeof(k_no_packet_id)];
    MQTTClientInit(&client, &net, 1000, sendbuf, sizeof(sendbuf),
                   readbuf, sizeof(readbuf));
    client.isconnected = 1;
    client.messageHandlers[0].topicFilter = "defenseclaw/1/1/1/verdict/resp";
    client.messageHandlers[0].fp = on_message;
    (void)MQTTYield(&client, 10);
    assert(callbacks == 0);
    puts("  PASS: malformed PUBLISH never reaches the message handler");
}

/* Control for the test above: the same harness delivers a valid PUBLISH. */
static void test_cycle_delivers_valid_publish(void) {
    memcpy(incoming, k_no_packet_id, sizeof(k_no_packet_id));
    incoming[1] = 0x22;
    incoming[sizeof(k_no_packet_id)] = 0x00;
    incoming[sizeof(k_no_packet_id) + 1] = 0x07;
    incoming_len = (int)sizeof(k_no_packet_id) + 2;
    incoming_pos = 0;
    callbacks = 0;
    Network net = {.my_socket = -1, .tls_active = false,
                   .mqttread = read_packet, .mqttwrite = write_packet};
    MQTTClient client = {0};
    unsigned char sendbuf[64], readbuf[sizeof(k_no_packet_id) + 2];
    MQTTClientInit(&client, &net, 1000, sendbuf, sizeof(sendbuf),
                   readbuf, sizeof(readbuf));
    client.isconnected = 1;
    client.messageHandlers[0].topicFilter = "defenseclaw/1/1/1/verdict/resp";
    client.messageHandlers[0].fp = on_message;
    (void)MQTTYield(&client, 10);
    assert(callbacks == 1);
    puts("  PASS: valid PUBLISH with packet id reaches the message handler");
}

int main(void) {
    printf("test_mqtt_publish_bounds:\n");
    test_deserialize_rejects_missing_packet_id();
    test_cycle_does_not_deliver_malformed_publish();
    test_cycle_delivers_valid_publish();
    return 0;
}
