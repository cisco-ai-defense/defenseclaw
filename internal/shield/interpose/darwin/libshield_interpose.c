/*
 * DefenseClaw Shield — macOS SSL Interposition Library
 *
 * Loaded via DYLD_INSERT_LIBRARIES. Exports SSL_write and SSL_read symbols
 * that shadow the real ones from libssl. Uses dlsym(RTLD_NEXT, ...) to find
 * the originals in the next library in load order.
 *
 * Build:
 *   clang -shared -fPIC -arch arm64 -o libshield_interpose.dylib \
 *         libshield_interpose.c -ldl
 *
 * Usage:
 *   DYLD_INSERT_LIBRARIES=./libshield_interpose.dylib \
 *   SHIELD_SOCKET=$HOME/.defenseclaw-shield/shield.sock \
 *   python3 my_agent.py
 *
 * NOTE: macOS SIP blocks DYLD_INSERT_LIBRARIES on Apple system binaries.
 *       Use non-system binaries (Homebrew python3, etc).
 */

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define MSG_TYPE_REQUEST  0x01
#define MSG_TYPE_RESPONSE 0x02
#define VERDICT_ALLOW     0x00
#define VERDICT_BLOCK     0x01

typedef int (*ssl_write_fn)(void *, const void *, int);
typedef int (*ssl_read_fn)(void *, void *, int);
typedef int (*ssl_get_fd_fn)(const void *);

static ssl_write_fn  orig_ssl_write  = NULL;
static ssl_read_fn   orig_ssl_read   = NULL;
static ssl_get_fd_fn orig_ssl_get_fd = NULL;

static pthread_key_t  sock_key;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static char socket_path[1024]  = {0};
static int  debug_enabled      = 0;

#define DBG(fmt, ...) do { \
    if (debug_enabled) fprintf(stderr, "[shield] " fmt "\n", ##__VA_ARGS__); \
} while(0)

static void close_sock(void *val) {
    int fd = (int)(intptr_t)val;
    if (fd > 0) close(fd);
}

static void do_init(void) {
    pthread_key_create(&sock_key, close_sock);
    debug_enabled = (getenv("SHIELD_DEBUG") != NULL);

    const char *p = getenv("SHIELD_SOCKET");
    if (p) {
        strncpy(socket_path, p, sizeof(socket_path) - 1);
    } else {
        const char *home = getenv("HOME");
        if (home)
            snprintf(socket_path, sizeof(socket_path),
                     "%s/.defenseclaw-shield/shield.sock", home);
    }

    orig_ssl_write  = (ssl_write_fn)dlsym(RTLD_NEXT, "SSL_write");
    orig_ssl_read   = (ssl_read_fn)dlsym(RTLD_NEXT, "SSL_read");
    orig_ssl_get_fd = (ssl_get_fd_fn)dlsym(RTLD_NEXT, "SSL_get_fd");

    DBG("init socket=%s write=%p read=%p get_fd=%p",
        socket_path, (void*)orig_ssl_write,
        (void*)orig_ssl_read, (void*)orig_ssl_get_fd);
}

static int daemon_fd(void) {
    int fd = (int)(intptr_t)pthread_getspecific(sock_key);
    if (fd > 0) return fd;
    if (socket_path[0] == '\0') return -1;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un sa = {0};
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, socket_path, sizeof(sa.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        DBG("connect failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    DBG("connected fd=%d", fd);
    pthread_setspecific(sock_key, (void *)(intptr_t)fd);
    return fd;
}

static void get_peer(const void *ssl, char *buf, size_t len) {
    buf[0] = '\0';
    if (!orig_ssl_get_fd) goto fallback;
    int fd = orig_ssl_get_fd(ssl);
    if (fd < 0) goto fallback;

    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) < 0) goto fallback;

    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        char ip[64]; inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof(ip));
        snprintf(buf, len, "%s:%d", ip, ntohs(s4->sin_port));
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        char ip[128]; inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof(ip));
        snprintf(buf, len, "[%s]:%d", ip, ntohs(s6->sin6_port));
    } else {
        goto fallback;
    }
    return;

fallback:
    snprintf(buf, len, "unknown:443");
}

static uint8_t check_with_daemon(uint8_t type, const void *ssl,
                                  const void *data, int dlen) {
    int fd = daemon_fd();
    if (fd < 0) return VERDICT_ALLOW;

    char host[256];
    get_peer(ssl, host, sizeof(host));
    uint16_t hlen = (uint16_t)strlen(host);
    uint32_t pid  = (uint32_t)getpid();
    uint32_t plen = (dlen > 0) ? (uint32_t)dlen : 0;

    uint32_t blen = 1 + 4 + 2 + hlen + 4 + plen;
    uint32_t total = 4 + blen;
    uint8_t *msg = (uint8_t *)malloc(total);
    if (!msg) return VERDICT_ALLOW;

    /* header: body length LE32 */
    msg[0] = blen & 0xFF; msg[1] = (blen>>8) & 0xFF;
    msg[2] = (blen>>16) & 0xFF; msg[3] = (blen>>24) & 0xFF;
    msg[4] = type;
    msg[5] = pid & 0xFF; msg[6] = (pid>>8) & 0xFF;
    msg[7] = (pid>>16) & 0xFF; msg[8] = (pid>>24) & 0xFF;
    msg[9] = hlen & 0xFF; msg[10] = (hlen>>8) & 0xFF;
    memcpy(msg+11, host, hlen);
    uint32_t o = 11 + hlen;
    msg[o] = plen & 0xFF; msg[o+1] = (plen>>8) & 0xFF;
    msg[o+2] = (plen>>16) & 0xFF; msg[o+3] = (plen>>24) & 0xFF;
    if (plen > 0) memcpy(msg+o+4, data, plen);

    ssize_t n = write(fd, msg, total);
    free(msg);
    if (n != (ssize_t)total) {
        close(fd); pthread_setspecific(sock_key, NULL);
        return VERDICT_ALLOW;
    }

    uint8_t v = VERDICT_ALLOW;
    n = read(fd, &v, 1);
    if (n != 1) {
        close(fd); pthread_setspecific(sock_key, NULL);
        return VERDICT_ALLOW;
    }
    DBG("%s %s → %s", type == MSG_TYPE_REQUEST ? "REQ" : "RSP",
        host, v == VERDICT_BLOCK ? "BLOCK" : "ALLOW");
    return v;
}

/* ---- Exported hooks — shadow the real SSL_write / SSL_read ---- */

int SSL_write(void *ssl, const void *buf, int num) {
    pthread_once(&init_once, do_init);
    if (!orig_ssl_write) { errno = ENOSYS; return -1; }

    uint8_t v = check_with_daemon(MSG_TYPE_REQUEST, ssl, buf, num);
    if (v == VERDICT_BLOCK) {
        DBG("BLOCKED SSL_write (%d bytes)", num);
        errno = EPERM;
        return -1;
    }
    return orig_ssl_write(ssl, buf, num);
}

int SSL_read(void *ssl, void *buf, int num) {
    pthread_once(&init_once, do_init);
    if (!orig_ssl_read) { errno = ENOSYS; return -1; }

    int ret = orig_ssl_read(ssl, buf, num);
    if (ret > 0)
        check_with_daemon(MSG_TYPE_RESPONSE, ssl, buf, ret);
    return ret;
}
