#define _GNU_SOURCE
#include "platform.h"
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#define FLASH_TOTAL_SIZE   (16 * 1024)

static const char *get_flash_path(void) {
    const char *env = getenv("DCLAW_FLASH_PATH");
    return env ? env : "/tmp/defenseclaw-lite-flash.bin";
}

static int flash_fd = -1;

uint32_t hal_tick_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int hal_flash_read(uint32_t offset, void *buf, size_t len) {
    if (flash_fd < 0) return -1;
    if (offset + len > FLASH_TOTAL_SIZE) return -1;
    if (pread(flash_fd, buf, len, (off_t)offset) != (ssize_t)len) return -1;
    return 0;
}

int hal_flash_write(uint32_t offset, const void *buf, size_t len) {
    if (flash_fd < 0) return -1;
    if (offset + len > FLASH_TOTAL_SIZE) return -1;
    if (pwrite(flash_fd, buf, len, (off_t)offset) != (ssize_t)len) return -1;
    if (fdatasync(flash_fd) != 0) return -1;
    return 0;
}

int hal_flash_erase_sector(uint32_t sector) {
    uint32_t offset = sector * 4096;
    if (offset + 4096 > FLASH_TOTAL_SIZE) return -1;
    uint8_t zeros[4096];
    memset(zeros, 0xFF, sizeof(zeros));
    return hal_flash_write(offset, zeros, sizeof(zeros));
}

int hal_ipc_socket_create(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFL, O_NONBLOCK);

    unlink(path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    chmod(path, 0660);

    if (listen(fd, 4) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int hal_ipc_socket_accept(int server_fd) {
    return accept(server_fd, NULL, NULL);
}

void hal_ipc_socket_close(int fd) {
    close(fd);
}

int hal_get_peer_cred(int fd, uint32_t *uid, uint32_t *gid, int32_t *pid) {
#ifdef __linux__
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) return -1;
    *uid = (uint32_t)cred.uid;
    *gid = (uint32_t)cred.gid;
    *pid = (int32_t)cred.pid;
    return 0;
#else
    (void)fd; (void)uid; (void)gid; (void)pid;
    return -1;
#endif
}

uint64_t hal_get_pid_start_time(int32_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    /* Field 22 in /proc/[pid]/stat is starttime (clock ticks since boot) */
    char buf[512];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    /* Skip past the comm field (enclosed in parentheses) */
    char *p = strrchr(buf, ')');
    if (!p) return 0;
    p += 2; /* skip ') ' */

    /* starttime is field 20 after the comm field (field 22 overall, 0-indexed from after ')') */
    uint64_t starttime = 0;
    int field = 0;
    while (*p && field < 19) {
        if (*p == ' ') field++;
        p++;
    }
    /* Now p points to starttime */
    starttime = (uint64_t)strtoull(p, NULL, 10);
    return starttime;
}

int hal_random_bytes(void *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

int hal_load_device_cert(uint8_t *cert_buf, size_t *cert_len, size_t max_len) {
    int fd = open("/etc/defenseclaw-lite/device.crt", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, cert_buf, max_len);
    close(fd);
    if (n <= 0) return -1;
    *cert_len = (size_t)n;
    return 0;
}

int hal_load_device_key(uint8_t *key_buf, size_t *key_len, size_t max_len) {
    int fd = open("/etc/defenseclaw-lite/device.key", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, key_buf, max_len);
    close(fd);
    if (n <= 0) return -1;
    *key_len = (size_t)n;
    return 0;
}

int hal_load_ca_cert(uint8_t *cert_buf, size_t *cert_len, size_t max_len) {
    int fd = open("/etc/defenseclaw-lite/ca.crt", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, cert_buf, max_len);
    close(fd);
    if (n <= 0) return -1;
    *cert_len = (size_t)n;
    return 0;
}

void hal_watchdog_feed(void) {
    /* Linux: no hardware watchdog in Phase 1. Could write to /dev/watchdog if needed. */
}

int hal_init(void) {
    const char *flash_path = get_flash_path();

    /* Open or create flash backing file */
    flash_fd = open(flash_path, O_RDWR | O_CREAT, 0640);
    if (flash_fd < 0) return -1;

    /* Ensure file is at least FLASH_TOTAL_SIZE */
    if (ftruncate(flash_fd, FLASH_TOTAL_SIZE) < 0) {
        close(flash_fd);
        flash_fd = -1;
        return -1;
    }
    return 0;
}

void hal_shutdown(void) {
    if (flash_fd >= 0) {
        close(flash_fd);
        flash_fd = -1;
    }
}
