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

#define _GNU_SOURCE
#include "platform.h"
#include "config.h"
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
#include <sys/file.h>

#define FLASH_TOTAL_SIZE   (16 * 1024)

/* Production flash files must live in a provisioned state directory. Each
 * prefix includes its trailing '/', so "/var/lib/defenseclawX/..." does
 * not match "/var/lib/defenseclaw/". */
bool hal_flash_path_is_provisioned(const char *path) {
    static const char *const prefixes[] = {
        "/var/lib/defenseclaw/",
        "/etc/defenseclaw/",
    };
    if (!path) return false;
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        if (strncmp(path, prefixes[i], strlen(prefixes[i])) == 0) return true;
    }
    return false;
}

static const char *get_flash_path(void) {
    const char *env = getenv("DCLAW_FLASH_PATH");
    if (env) {
        /* Reject path traversal to prevent writing outside intended directory */
        if (strstr(env, "..") != NULL) {
            fprintf(stderr, "[DCLAW] ERROR: DCLAW_FLASH_PATH must not contain '..'\n");
            return NULL;
        }
#if !DCLAW_DEV_MODE
        if (!hal_flash_path_is_provisioned(env)) {
            fprintf(stderr, "[DCLAW] ERROR: DCLAW_FLASH_PATH must be under /var/lib/defenseclaw/ or /etc/defenseclaw/ in production\n");
            return NULL;
        }
#endif
        return env;
    }
    return "/var/lib/defenseclaw/flash.bin";
}

static int flash_fd = -1;
static hal_flash_stats_t flash_stats;

void hal_flash_get_stats(hal_flash_stats_t *out) {
    if (out) *out = flash_stats;
}

uint64_t hal_tick_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

int hal_flash_read(uint32_t offset, void *buf, size_t len) {
    if (flash_fd < 0) return -1;
    if (offset > FLASH_TOTAL_SIZE || len > FLASH_TOTAL_SIZE - (size_t)offset) return -1;
    if (pread(flash_fd, buf, len, (off_t)offset) != (ssize_t)len) return -1;
    return 0;
}

int hal_flash_write(uint32_t offset, const void *buf, size_t len) {
    if (flash_fd < 0) return -1;
    if (offset > FLASH_TOTAL_SIZE || len > FLASH_TOTAL_SIZE - (size_t)offset) return -1;
    if (pwrite(flash_fd, buf, len, (off_t)offset) != (ssize_t)len) return -1;
    flash_stats.writes++;
    flash_stats.bytes_written += len;
    return 0;
}

static unsigned flash_sync_failures;

void hal_flash_fail_next_syncs(unsigned n) {
    flash_sync_failures = n;
}

int hal_flash_sync(void) {
    if (flash_fd < 0) return -1;
    if (flash_sync_failures > 0) {
        flash_sync_failures--;
        return -1;
    }
    if (fdatasync(flash_fd) != 0) return -1;
    flash_stats.syncs++;
    return 0;
}

int hal_flash_erase_sector(uint32_t sector) {
    uint32_t offset = sector * 4096;
    if (offset + 4096 > FLASH_TOTAL_SIZE) return -1;
    uint8_t zeros[4096];
    memset(zeros, 0xFF, sizeof(zeros));
    /* The file-backed erase is a 4 KiB write; it is also counted as one. */
    if (hal_flash_write(offset, zeros, sizeof(zeros)) != 0) return -1;
    flash_stats.erases++;
    return 0;
}

int hal_ipc_socket_create(const char *path) {
#ifdef SOCK_CLOEXEC
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
#endif
    if (fd < 0) return -1;
    fcntl(fd, F_SETFL, O_NONBLOCK);

    mode_t old_mask = umask(0117);

    /* Best-effort unlink — if it fails (ENOENT), that's fine.
     * If the path is a non-socket, bind() will fail safely. */
    unlink(path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        umask(old_mask);
        close(fd);
        return -1;
    }

    /* If running as root, chown the socket to the expected IPC
     * UID/GID so that the non-root user can connect.  The expected_uid/gid
     * are set from DCLAW_IPC_ALLOWED_UID/GID env vars or getuid()/getgid()
     * in main.c after dclaw_init(). */
    if (getuid() == 0) {
        const char *env_uid = getenv("DCLAW_IPC_ALLOWED_UID");
        const char *env_gid = getenv("DCLAW_IPC_ALLOWED_GID");
        if (env_uid || env_gid) {
            char *end_uid = NULL, *end_gid = NULL;
            unsigned long raw_uid = env_uid ? strtoul(env_uid, &end_uid, 10) : 0;
            unsigned long raw_gid = env_gid ? strtoul(env_gid, &end_gid, 10) : 0;
            if ((env_uid && (end_uid == env_uid || *end_uid != '\0')) ||
                (env_gid && (end_gid == env_gid || *end_gid != '\0'))) {
                fprintf(stderr, "[DCLAW] ERROR: DCLAW_IPC_ALLOWED_UID/GID must be numeric\n");
                close(fd);
                return -1;
            }
            uid_t sock_uid = (uid_t)raw_uid;
            gid_t sock_gid = (gid_t)raw_gid;
            if (chown(path, sock_uid, sock_gid) != 0) {
                fprintf(stderr, "[DCLAW] WARN: failed to chown IPC socket to %u:%u\n",
                        (unsigned)sock_uid, (unsigned)sock_gid);
            }
        }
    }

    if (listen(fd, 4) < 0) {
        umask(old_mask);
        close(fd);
        return -1;
    }
    umask(old_mask);
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

    char *p = strrchr(buf, ')');
    if (!p) return 0;
    p += 2;
    char *buf_end = buf + sizeof(buf);

    uint64_t starttime = 0;
    int field = 0;
    while (p < buf_end && *p && field < 19) {
        if (*p == ' ') field++;
        p++;
    }
    if (p >= buf_end) return 0;
    /* Now p points to starttime */
    starttime = (uint64_t)strtoull(p, NULL, 10);
    return starttime;
}

int hal_random_bytes(void *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

/* Read a file fully into buf with EINTR retry. Returns bytes read or -1. */
static ssize_t read_file_full(int fd, uint8_t *buf, size_t max_len) {
    size_t total = 0;
    while (total < max_len) {
        ssize_t n = read(fd, buf + total, max_len - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) break; /* EOF */
        total += (size_t)n;
    }
    return (ssize_t)total;
}

int hal_load_device_cert(uint8_t *cert_buf, size_t *cert_len, size_t max_len) {
    int fd = open("/etc/edge-connector/device.crt", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read_file_full(fd, cert_buf, max_len);
    /* Detect truncation: if we filled max_len, there may be more data */
    if (n == (ssize_t)max_len) {
        uint8_t extra;
        if (read(fd, &extra, 1) > 0) {
            close(fd);
            fprintf(stderr, "[DCLAW] ERROR: device cert exceeds %zu bytes (truncated)\n", max_len);
            return -1;
        }
    }
    close(fd);
    if (n <= 0) return -1;
    *cert_len = (size_t)n;
    return 0;
}

int hal_load_device_key(uint8_t *key_buf, size_t *key_len, size_t max_len) {
    int fd = open("/etc/edge-connector/device.key", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read_file_full(fd, key_buf, max_len);
    close(fd);
    if (n <= 0) return -1;
    *key_len = (size_t)n;
    return 0;
}

int hal_load_ca_cert(uint8_t *cert_buf, size_t *cert_len, size_t max_len) {
    int fd = open("/etc/edge-connector/ca.crt", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read_file_full(fd, cert_buf, max_len);
    if (n == (ssize_t)max_len) {
        uint8_t extra;
        if (read(fd, &extra, 1) > 0) {
            close(fd);
            fprintf(stderr, "[DCLAW] ERROR: CA cert exceeds %zu bytes (truncated)\n", max_len);
            return -1;
        }
    }
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
    if (!flash_path) return -1;

    /* Create parent directory if it doesn't exist.
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
                    fprintf(stderr, "[DCLAW] ERROR: cannot create %s (%s) and "
                            "/tmp fallback is disabled in production. "
                            "Create the directory with: sudo mkdir -p %s && sudo chown $(id -u) %s\n",
                            dir, strerror(errno), dir, dir);
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
     * Use 0600 (owner-only) to prevent group-readable access,
     * especially important when falling back to /tmp.
     * O_NOFOLLOW: Prevent symlink attacks — if the path is a symlink, open()
     * will fail with ELOOP instead of following it. */
    /* Re-initialisation in the same process reopens the file. */
    if (flash_fd >= 0) {
        close(flash_fd);
        flash_fd = -1;
    }
    flash_fd = open(flash_path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (flash_fd < 0) return -1;

    /* Exactly one engine may own a flash file. Each engine keeps the audit
     * ring head, HMAC chain, boot counter and emergency records in RAM, so
     * two engines on one file (the daemon and an in-process library, or two
     * daemons) overwrite each other's entries and break the audit chain. */
    if (flock(flash_fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            fprintf(stderr, "[DCLAW] ERROR: flash file %s is in use by another DefenseClaw "
                    "engine (daemon or in-process library); refusing to start. "
                    "Use the daemon's IPC socket, or give this engine its own DCLAW_FLASH_PATH.\n",
                    flash_path);
        } else {
            fprintf(stderr, "[DCLAW] ERROR: cannot lock flash file %s: %s\n",
                    flash_path, strerror(errno));
        }
        close(flash_fd);
        flash_fd = -1;
        return -1;
    }

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
