#define _GNU_SOURCE
#include "platform.h"
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#define FLASH_TOTAL_SIZE   (16 * 1024)

static const char *get_flash_path(void) {
    const char *env = getenv("DCLAW_FLASH_PATH");
    return env ? env : "/var/lib/defenseclaw/flash.bin";
}

static int flash_fd = -1;

uint64_t hal_tick_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

int hal_flash_read(uint32_t offset, void *buf, size_t len) {
    if (flash_fd < 0) return -1;
    /* L-2 fix: Cast to size_t before addition to prevent integer overflow
     * on 32-bit platforms where uint32_t + size_t could wrap. */
    if ((size_t)offset + len > FLASH_TOTAL_SIZE) return -1;
    if (pread(flash_fd, buf, len, (off_t)offset) != (ssize_t)len) return -1;
    return 0;
}

int hal_flash_write(uint32_t offset, const void *buf, size_t len) {
    if (flash_fd < 0) return -1;
    /* L-2 fix: Cast to size_t before addition to prevent integer overflow
     * on 32-bit platforms where uint32_t + size_t could wrap. */
    if ((size_t)offset + len > FLASH_TOTAL_SIZE) return -1;
    if (pwrite(flash_fd, buf, len, (off_t)offset) != (ssize_t)len) return -1;
    return 0;
}

int hal_flash_sync(void) {
    if (flash_fd < 0) return -1;
    return fdatasync(flash_fd);
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

    /* Prevent symlink attack: only unlink if path is a socket or doesn't exist */
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            /* Path exists but is not a socket — refuse to unlink */
            close(fd);
            return -1;
        }
        unlink(path);
    }
    /* else: ENOENT — path doesn't exist, no unlink needed */

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    chmod(path, 0660);

    /* P1 fix: If running as root, chown the socket to the expected IPC
     * UID/GID so that the non-root user can connect.  The expected_uid/gid
     * are set from DCLAW_IPC_ALLOWED_UID/GID env vars or getuid()/getgid()
     * in main.c after dclaw_init(). */
    if (getuid() == 0) {
        const char *env_uid = getenv("DCLAW_IPC_ALLOWED_UID");
        const char *env_gid = getenv("DCLAW_IPC_ALLOWED_GID");
        if (env_uid || env_gid) {
            uid_t sock_uid = env_uid ? (uid_t)strtoul(env_uid, NULL, 10) : 0;
            gid_t sock_gid = env_gid ? (gid_t)strtoul(env_gid, NULL, 10) : 0;
            if (chown(path, sock_uid, sock_gid) != 0) {
                fprintf(stderr, "[DCLAW] WARN: failed to chown IPC socket to %u:%u\n",
                        (unsigned)sock_uid, (unsigned)sock_gid);
            }
        }
    }

    if (listen(fd, 4) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int hal_ipc_socket_accept(int server_fd) {
    int fd = accept(server_fd, NULL, NULL);
    if (fd >= 0) {
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    }
    return fd;
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
    int fd = open("/etc/edge-connector/device.crt", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, cert_buf, max_len);
    close(fd);
    if (n <= 0) return -1;
    *cert_len = (size_t)n;
    return 0;
}

int hal_load_device_key(uint8_t *key_buf, size_t *key_len, size_t max_len) {
    int fd = open("/etc/edge-connector/device.key", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, key_buf, max_len);
    close(fd);
    if (n <= 0) return -1;
    *key_len = (size_t)n;
    return 0;
}

int hal_load_ca_cert(uint8_t *cert_buf, size_t *cert_len, size_t max_len) {
    int fd = open("/etc/edge-connector/ca.crt", O_RDONLY);
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

/* Recursively create directories (like mkdir -p).
 * Returns 0 on success, -1 on failure. */
static int mkdir_p(const char *path, mode_t mode) {
    char tmp[256];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(tmp)) return -1;
    memcpy(tmp, path, len + 1);

    /* Strip trailing slash */
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* Extract the parent directory from a file path.
 * Writes into buf (up to buf_size).  Returns buf on success, NULL on failure. */
static char *parent_dir(const char *filepath, char *buf, size_t buf_size) {
    const char *last_slash = strrchr(filepath, '/');
    if (!last_slash || last_slash == filepath) return NULL;
    size_t len = (size_t)(last_slash - filepath);
    if (len >= buf_size) return NULL;
    memcpy(buf, filepath, len);
    buf[len] = '\0';
    return buf;
}

int hal_init(void) {
    const char *flash_path = get_flash_path();

    /* P1 fix: Create parent directory if it doesn't exist.
     * On pristine hosts /var/lib/defenseclaw/ won't exist, causing open()
     * to fail with ENOENT.  We create it recursively (mode 0700) and fall
     * back to /tmp/ if that fails (e.g., permission denied). */
    {
        char dir_buf[256];
        char *dir = parent_dir(flash_path, dir_buf, sizeof(dir_buf));
        if (dir) {
            struct stat st;
            if (stat(dir, &st) != 0) {
                if (mkdir_p(dir, 0700) != 0) {
#if !DCLAW_DEV_MODE
                    /* H-5 fix: In production, refuse to use /tmp/ — it's
                     * world-writable and any local user can tamper with
                     * policy, audit, and emergency state. */
                    fprintf(stderr, "[DCLAW] ERROR: cannot create %s (%s) and "
                            "/tmp fallback is disabled in production. "
                            "Create the directory with: sudo mkdir -p %s && sudo chown $(id -u) %s\n",
                            dir, strerror(errno), dir, dir);
                    free(dir);
                    return -1;
#else
                    fprintf(stderr, "[DCLAW] WARNING: cannot create %s (%s); "
                            "falling back to /tmp/ — insecure, for dev only\n",
                            dir, strerror(errno));
                    flash_path = "/tmp/defenseclaw-flash.bin";
#endif
                }
            }
        }
    }

    /* Open or create flash backing file.
     * M-12 fix: Use 0600 (owner-only) instead of 0640 to prevent group-readable
     * access, especially important when falling back to /tmp. */
    flash_fd = open(flash_path, O_RDWR | O_CREAT, 0600);
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
