#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>

/*
 * TLS engine wrapper — mbedTLS implementation.
 *
 * When DCLAW_HAS_MBEDTLS is defined and non-zero, this file provides a
 * real TLS transport using mbedTLS for mTLS handshake + session management.
 *
 * When mbedTLS is not available (DCLAW_HAS_MBEDTLS == 0 or undefined),
 * the functions return -1 stubs so any TLS code path fails loudly.
 *
 * Environment variables:
 *   DCLAW_CA_CERT_PATH     — PEM file for CA certificate (server verification)
 *   DCLAW_DEVICE_CERT_PATH — PEM file for device certificate (mTLS client cert)
 *   DCLAW_DEVICE_KEY_PATH  — PEM file for device private key (mTLS client key)
 */

#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>

/* ---------- static TLS state ---------- */

static mbedtls_ssl_context       tls_ssl;
static mbedtls_ssl_config        tls_conf;
static mbedtls_ctr_drbg_context  tls_drbg;
static mbedtls_entropy_context   tls_entropy;
static mbedtls_x509_crt          tls_ca_cert;
static mbedtls_x509_crt          tls_device_cert;
static mbedtls_pk_context        tls_device_key;
static mbedtls_net_context       tls_net;
static bool                      tls_initialized = false;

/* Helper: read an entire file into a malloc'd buffer (NUL-terminated for PEM).
 * Returns the buffer on success (caller frees), NULL on failure.
 * *out_len includes the trailing NUL byte (as mbedtls_x509_crt_parse expects). */
static unsigned char *read_file_alloc(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0) { fclose(f); return NULL; }
    if (fsize > 65536) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);

    /* +1 for NUL terminator (PEM parsing requires it) */
    unsigned char *buf = malloc((size_t)fsize + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t nread = fread(buf, 1, (size_t)fsize, f);
    fclose(f);
    if ((long)nread != fsize) { free(buf); return NULL; }

    buf[nread] = '\0';
    *out_len = nread + 1;
    return buf;
}

/* ---------- public API ---------- */

int dclaw_tls_init(void) {
    int ret;

    /* Prevent double-init */
    if (tls_initialized) return 0;

    /* 1. Init all contexts */
    mbedtls_ssl_init(&tls_ssl);
    mbedtls_ssl_config_init(&tls_conf);
    mbedtls_ctr_drbg_init(&tls_drbg);
    mbedtls_entropy_init(&tls_entropy);
    mbedtls_x509_crt_init(&tls_ca_cert);
    mbedtls_x509_crt_init(&tls_device_cert);
    mbedtls_pk_init(&tls_device_key);
    mbedtls_net_init(&tls_net);

    /* 2. Seed the DRBG from entropy */
    const char *pers = "defenseclaw_tls";
    ret = mbedtls_ctr_drbg_seed(&tls_drbg, mbedtls_entropy_func, &tls_entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        char errbuf[128];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "[DCLAW-TLS] DRBG seed failed: %s (0x%04x)\n", errbuf, (unsigned)-ret);
        goto fail;
    }

    /* 3. Configure as TLS client */
    ret = mbedtls_ssl_config_defaults(&tls_conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        char errbuf[128];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "[DCLAW-TLS] ssl_config_defaults failed: %s (0x%04x)\n", errbuf, (unsigned)-ret);
        goto fail;
    }

    mbedtls_ssl_conf_rng(&tls_conf, mbedtls_ctr_drbg_random, &tls_drbg);

    /* CRT-1 fix: Always default to VERIFY_REQUIRED regardless of profile.
     * The only way to downgrade is the explicit DCLAW_TLS_INSECURE=1 env
     * var combined with no CA cert — see the fallback check below. */
    mbedtls_ssl_conf_authmode(&tls_conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    /* CRT-3 fix: Enforce TLS 1.2 minimum to prevent downgrade attacks
     * (BEAST, POODLE, Lucky13 on TLS 1.0/1.1). */
    mbedtls_ssl_conf_min_version(&tls_conf,
                                  MBEDTLS_SSL_MAJOR_VERSION_3,
                                  MBEDTLS_SSL_MINOR_VERSION_3); /* TLS 1.2 */

    /* H-1 fix: Set handshake timeout to prevent blocking forever on
     * stalled servers. 10 seconds min, 30 seconds max. */
    mbedtls_ssl_conf_handshake_timeout(&tls_conf, 10000, 30000);

    /* 4. Load CA certificate if DCLAW_CA_CERT_PATH is set */
    const char *ca_path = getenv("DCLAW_CA_CERT_PATH");
    if (ca_path && ca_path[0]) {
        size_t ca_len = 0;
        unsigned char *ca_buf = read_file_alloc(ca_path, &ca_len);
        if (!ca_buf) {
            fprintf(stderr, "[DCLAW-TLS] Failed to read CA cert: %s\n", ca_path);
            goto fail;
        }
        ret = mbedtls_x509_crt_parse(&tls_ca_cert, ca_buf, ca_len);
        explicit_bzero(ca_buf, ca_len);
        free(ca_buf);
        if (ret != 0) {
            char errbuf[128];
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            fprintf(stderr, "[DCLAW-TLS] CA cert parse failed: %s (0x%04x)\n", errbuf, (unsigned)-ret);
            goto fail;
        }
        mbedtls_ssl_conf_ca_chain(&tls_conf, &tls_ca_cert, NULL);
        fprintf(stderr, "[DCLAW-TLS] CA certificate loaded from %s\n", ca_path);
    } else {
        /* CRT-1 fix: No CA cert provided. Only downgrade to VERIFY_OPTIONAL
         * when the operator explicitly sets DCLAW_TLS_INSECURE=1. This is a
         * deliberate opt-in for development/lab environments. Without this
         * env var, refuse to connect without a CA cert. */
        const char *insecure = getenv("DCLAW_TLS_INSECURE");
        if (insecure && strcmp(insecure, "1") == 0) {
            fprintf(stderr, "[DCLAW-TLS] WARNING: No CA cert and DCLAW_TLS_INSECURE=1 — "
                    "downgrading to VERIFY_OPTIONAL. DO NOT USE IN PRODUCTION.\n");
            mbedtls_ssl_conf_authmode(&tls_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        } else {
            fprintf(stderr, "[DCLAW-TLS] ERROR: No CA cert (DCLAW_CA_CERT_PATH unset) "
                    "and DCLAW_TLS_INSECURE is not 1 — refusing to connect without "
                    "server verification.\n");
            goto fail;
        }
    }

    /* 5. Load device certificate + key for mTLS (if both paths are set) */
    const char *cert_path = getenv("DCLAW_DEVICE_CERT_PATH");
    const char *key_path  = getenv("DCLAW_DEVICE_KEY_PATH");
    if (cert_path && cert_path[0] && key_path && key_path[0]) {
        /* Parse device certificate */
        size_t cert_len = 0;
        unsigned char *cert_buf = read_file_alloc(cert_path, &cert_len);
        if (!cert_buf) {
            fprintf(stderr, "[DCLAW-TLS] Failed to read device cert: %s\n", cert_path);
            goto fail;
        }
        ret = mbedtls_x509_crt_parse(&tls_device_cert, cert_buf, cert_len);
        explicit_bzero(cert_buf, cert_len);
        free(cert_buf);
        if (ret != 0) {
            char errbuf[128];
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            fprintf(stderr, "[DCLAW-TLS] Device cert parse failed: %s (0x%04x)\n", errbuf, (unsigned)-ret);
            goto fail;
        }

        /* Parse device private key (no password) */
        size_t key_len = 0;
        unsigned char *key_buf = read_file_alloc(key_path, &key_len);
        if (!key_buf) {
            fprintf(stderr, "[DCLAW-TLS] Failed to read device key: %s\n", key_path);
            goto fail;
        }
#if MBEDTLS_VERSION_MAJOR >= 3
        ret = mbedtls_pk_parse_key(&tls_device_key, key_buf, key_len,
                                   NULL, 0, mbedtls_ctr_drbg_random, &tls_drbg);
#else
        ret = mbedtls_pk_parse_key(&tls_device_key, key_buf, key_len, NULL, 0);
#endif
        explicit_bzero(key_buf, key_len);
        free(key_buf);
        if (ret != 0) {
            char errbuf[128];
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            fprintf(stderr, "[DCLAW-TLS] Device key parse failed: %s (0x%04x)\n", errbuf, (unsigned)-ret);
            goto fail;
        }

        ret = mbedtls_ssl_conf_own_cert(&tls_conf, &tls_device_cert, &tls_device_key);
        if (ret != 0) {
            char errbuf[128];
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            fprintf(stderr, "[DCLAW-TLS] ssl_conf_own_cert failed: %s (0x%04x)\n", errbuf, (unsigned)-ret);
            goto fail;
        }
        fprintf(stderr, "[DCLAW-TLS] Device cert+key loaded for mTLS (%s, %s)\n", cert_path, key_path);
    }

    /* 6. Apply config to SSL context */
    ret = mbedtls_ssl_setup(&tls_ssl, &tls_conf);
    if (ret != 0) {
        char errbuf[128];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "[DCLAW-TLS] ssl_setup failed: %s (0x%04x)\n", errbuf, (unsigned)-ret);
        goto fail;
    }

    tls_initialized = true;
    fprintf(stderr, "[DCLAW-TLS] TLS engine initialized\n");
    return 0;

fail:
    mbedtls_ssl_free(&tls_ssl);
    mbedtls_ssl_config_free(&tls_conf);
    mbedtls_ctr_drbg_free(&tls_drbg);
    mbedtls_entropy_free(&tls_entropy);
    mbedtls_x509_crt_free(&tls_ca_cert);
    mbedtls_x509_crt_free(&tls_device_cert);
    mbedtls_pk_free(&tls_device_key);
    mbedtls_net_free(&tls_net);
    return -1;
}

int dclaw_tls_connect(int tcp_fd, const char *hostname) {
    if (!tls_initialized) {
        fprintf(stderr, "[DCLAW-TLS] ERROR: tls_connect called before tls_init\n");
        return -1;
    }

    /* Reset the SSL session state for a fresh handshake (allows reconnect) */
    int ret = mbedtls_ssl_session_reset(&tls_ssl);
    if (ret != 0) {
        char errbuf[128];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "[DCLAW-TLS] ssl_session_reset failed: %s (0x%04x)\n", errbuf, (unsigned)-ret);
        return -1;
    }

    /* CRT-2 fix: Set hostname for SNI and certificate verification.
     * Without this, any valid certificate is accepted regardless of domain. */
    if (hostname && hostname[0]) {
        ret = mbedtls_ssl_set_hostname(&tls_ssl, hostname);
        if (ret != 0) {
            fprintf(stderr, "[DCLAW-TLS] set_hostname(%s) failed: 0x%04x\n",
                    hostname, (unsigned)-ret);
            return -1;
        }
    }

    /* Wrap the existing TCP socket FD in an mbedtls_net_context */
    tls_net.fd = tcp_fd;

    mbedtls_ssl_set_bio(&tls_ssl, &tls_net,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

    /* Perform the TLS handshake, looping on WANT_READ / WANT_WRITE */
    do {
        ret = mbedtls_ssl_handshake(&tls_ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret != 0) {
        char errbuf[128];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "[DCLAW-TLS] Handshake failed: %s (0x%04x)\n", errbuf, (unsigned)-ret);
        return -1;
    }

    fprintf(stderr, "[DCLAW-TLS] Handshake complete (protocol: %s, cipher: %s)\n",
            mbedtls_ssl_get_version(&tls_ssl),
            mbedtls_ssl_get_ciphersuite(&tls_ssl));

    /* H-5 fix: Set timeout BIO once during connect so dclaw_tls_read does not
     * need to mutate global config on every call. Default to 30s read timeout. */
    mbedtls_ssl_conf_read_timeout(&tls_conf, 30000);
    mbedtls_ssl_set_bio(&tls_ssl, &tls_net,
                        mbedtls_net_send, NULL, mbedtls_net_recv_timeout);

    return 0;
}

int dclaw_tls_write(const uint8_t *data, size_t len) {
    if (!tls_initialized) return -1;

    size_t sent = 0;
    while (sent < len) {
        int ret = mbedtls_ssl_write(&tls_ssl, data + sent, len - sent);
        if (ret > 0) {
            sent += (size_t)ret;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
                   ret == MBEDTLS_ERR_SSL_WANT_READ) {
            /* Non-blocking: retry */
            continue;
        } else {
            char errbuf[128];
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            fprintf(stderr, "[DCLAW-TLS] Write error: %s (0x%04x)\n", errbuf, (unsigned)-ret);
            return -1;
        }
    }
    return (sent > INT_MAX) ? INT_MAX : (int)sent;
}

int dclaw_tls_read(uint8_t *buf, size_t len, int timeout_ms) {
    if (!tls_initialized) return -1;

    /* H-5 fix: Only update timeout value — BIO is already set to use
     * mbedtls_net_recv_timeout from dclaw_tls_connect(). */
    if (timeout_ms >= 0) {
        mbedtls_ssl_conf_read_timeout(&tls_conf, (uint32_t)timeout_ms);
    }

    int ret = mbedtls_ssl_read(&tls_ssl, buf, len);

    if (ret > 0) {
        return ret;
    } else if (ret == 0) {
        /* EOF / peer closed */
        return -1;
    } else if (ret == MBEDTLS_ERR_SSL_TIMEOUT ||
               ret == MBEDTLS_ERR_SSL_WANT_READ) {
        /* M-3 fix: Return -2 for timeout so callers can distinguish
         * "no data yet / timeout" from "fatal error / connection lost".
         * Callers should retry on -2, close on -1. */
        return -2;
    } else {
        char errbuf[128];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "[DCLAW-TLS] Read error: %s (0x%04x)\n", errbuf, (unsigned)-ret);
        return -1;
    }
}

void dclaw_tls_shutdown(void) {
    if (!tls_initialized) return;

    /* Send close_notify (best-effort, ignore errors) */
    int ret;
    do {
        ret = mbedtls_ssl_close_notify(&tls_ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    /* Free all contexts */
    mbedtls_ssl_free(&tls_ssl);
    mbedtls_ssl_config_free(&tls_conf);
    mbedtls_ctr_drbg_free(&tls_drbg);
    mbedtls_entropy_free(&tls_entropy);
    mbedtls_x509_crt_free(&tls_ca_cert);
    mbedtls_x509_crt_free(&tls_device_cert);
    mbedtls_pk_free(&tls_device_key);
    /* H-3 fix: mbedtls_net_free closes the fd. Set it to -1 so the caller
     * (mqtt_client.c) does not double-close in mqtt_mark_disconnected(). */
    mbedtls_net_free(&tls_net);
    tls_net.fd = -1;

    tls_initialized = false;
    fprintf(stderr, "[DCLAW-TLS] TLS engine shut down\n");
}

#else /* DCLAW_HAS_MBEDTLS not available */

/*
 * Stub implementations — always return failure.
 * Any code path that attempts TLS without mbedTLS will fail loudly.
 */

int  dclaw_tls_init(void)                                          { return -1; }
int  dclaw_tls_connect(int tcp_fd, const char *hostname)            { (void)tcp_fd; (void)hostname; return -1; }
int  dclaw_tls_write(const uint8_t *data, size_t len)              { (void)data; (void)len; return -1; }
int  dclaw_tls_read(uint8_t *buf, size_t len, int timeout_ms)      { (void)buf; (void)len; (void)timeout_ms; return -1; }
void dclaw_tls_shutdown(void)                                       {}

#endif /* DCLAW_HAS_MBEDTLS */
