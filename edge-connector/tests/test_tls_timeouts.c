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


/* TLS I/O must never block the daemon's single event loop indefinitely:
 * a peer that accepts TCP but stalls the handshake, or stops reading so the
 * send window fills, used to block dclaw_tls_connect forever or make
 * dclaw_tls_write spin at 100% CPU forever. */

#include "defenseclaw.h"
#include "platform.h"
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/net_sockets.h>
#if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_PROTO_TLS1_3)
#include <psa/crypto.h>
#endif

static mbedtls_entropy_context  g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_pk_context       g_key;
static mbedtls_x509_crt         g_crt;
static unsigned char            g_pem[4096];

static void make_self_signed(const char *pem_path) {
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_drbg);
    assert(mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                                 (const unsigned char *)"tls-test", 8) == 0);
    mbedtls_pk_init(&g_key);
    assert(mbedtls_pk_setup(&g_key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) == 0);
    assert(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(g_key),
                               mbedtls_ctr_drbg_random, &g_drbg) == 0);

    mbedtls_x509write_cert w;
    mbedtls_x509write_crt_init(&w);
    mbedtls_x509write_crt_set_version(&w, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&w, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&w, &g_key);
    mbedtls_x509write_crt_set_issuer_key(&w, &g_key);
    assert(mbedtls_x509write_crt_set_subject_name(&w, "CN=localhost") == 0);
    assert(mbedtls_x509write_crt_set_issuer_name(&w, "CN=localhost") == 0);
    unsigned char serial[] = { 0x01 };
    assert(mbedtls_x509write_crt_set_serial_raw(&w, serial, sizeof(serial)) == 0);
    assert(mbedtls_x509write_crt_set_validity(&w, "20200101000000", "20991231235959") == 0);
    assert(mbedtls_x509write_crt_set_basic_constraints(&w, 1, -1) == 0);
    assert(mbedtls_x509write_crt_pem(&w, g_pem, sizeof(g_pem),
                                     mbedtls_ctr_drbg_random, &g_drbg) == 0);
    mbedtls_x509write_crt_free(&w);

    mbedtls_x509_crt_init(&g_crt);
    assert(mbedtls_x509_crt_parse(&g_crt, g_pem, strlen((char *)g_pem) + 1) == 0);
    FILE *f = fopen(pem_path, "wb");
    assert(f);
    fwrite(g_pem, 1, strlen((char *)g_pem), f);
    fclose(f);
}

typedef struct {
    int fd;
    volatile int handshake_rc;
    volatile int stop;
} server_t;

/* Completes the handshake, then never reads again. */
static void *serve(void *arg) {
    server_t *sv = arg;
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    mbedtls_net_context net = { .fd = sv->fd };
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_init(&ssl);
    assert(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT) == 0);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &g_drbg);
    assert(mbedtls_ssl_conf_own_cert(&conf, &g_crt, &g_key) == 0);
    assert(mbedtls_ssl_setup(&ssl, &conf) == 0);
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);
    int rc;
    do {
        rc = mbedtls_ssl_handshake(&ssl);
    } while (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE);
    sv->handshake_rc = rc;
    while (!sv->stop) usleep(10000);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    return NULL;
}

static void test_handshake_deadline(void) {
    int sp[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    dclaw_tls_set_handshake_timeout(300);
    uint64_t t0 = hal_tick_ms();
    int rc = dclaw_tls_connect(sp[0], "localhost"); /* the peer never answers */
    uint64_t elapsed = hal_tick_ms() - t0;
    printf("    handshake rc=%d after %llu ms\n", rc, (unsigned long long)elapsed);
    assert(rc == -1);
    assert(elapsed < 3000);
    close(sp[0]);
    close(sp[1]);
    dclaw_tls_set_handshake_timeout(0);
    (void)rc; (void)elapsed;
    printf("  PASS: stalled TLS handshake gives up at its deadline\n");
}

static void test_write_deadline(void) {
    int sp[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    server_t sv = { .fd = sp[1], .handshake_rc = 1, .stop = 0 };
    pthread_t th;
    assert(pthread_create(&th, NULL, serve, &sv) == 0);
    assert(dclaw_tls_connect(sp[0], "localhost") == 0);
    while (sv.handshake_rc == 1) usleep(1000);
    assert(sv.handshake_rc == 0);
    /* The MQTT client runs the socket non-blocking after connect. */
    int fl = fcntl(sp[0], F_GETFL, 0);
    assert(fcntl(sp[0], F_SETFL, fl | O_NONBLOCK) == 0);

    size_t len = 8u << 20; /* far more than the socket buffers hold */
    uint8_t *buf = calloc(1, len);
    assert(buf);
    uint64_t t0 = hal_tick_ms();
    int rc = dclaw_tls_write(buf, len, 300);
    uint64_t elapsed = hal_tick_ms() - t0;
    printf("    write rc=%d after %llu ms\n", rc, (unsigned long long)elapsed);
    assert(rc == -1);
    assert(elapsed < 3000);
    free(buf);
    sv.stop = 1;
    pthread_join(th, NULL);
    close(sp[0]);
    close(sp[1]);
    (void)rc; (void)elapsed;
    printf("  PASS: TLS write to a peer that stopped reading gives up at its deadline\n");
}

int main(void) {
#if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_PROTO_TLS1_3)
    assert(psa_crypto_init() == PSA_SUCCESS);
#endif
    printf("test_tls_timeouts:\n");
    make_self_signed("tls-timeouts-ca.pem");
    setenv("DCLAW_CA_CERT_PATH", "tls-timeouts-ca.pem", 1);
    assert(dclaw_tls_init() == 0);
    test_handshake_deadline();
    test_write_deadline();
    dclaw_tls_shutdown();
    unlink("tls-timeouts-ca.pem");
    return 0;
}
