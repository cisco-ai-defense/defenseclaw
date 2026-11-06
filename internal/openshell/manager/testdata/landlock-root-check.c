// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
// Test helper: allow reads beneath the root's children, with no write rule
// on the root itself, then run the requested program.
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
                      LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 3) return 77;
    unsigned long long rights = LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
        LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
        LANDLOCK_ACCESS_FS_REFER;
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
    rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
    struct landlock_ruleset_attr ruleset = {.handled_access_fs = rights};
    int fd = syscall(SYS_landlock_create_ruleset, &ruleset, sizeof(ruleset), 0);
    if (fd < 0) return 3;
    DIR *root = opendir("/");
    if (!root) return 4;
    struct dirent *entry;
    while ((entry = readdir(root)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char path[512];
        if (snprintf(path, sizeof(path), "/%s", entry->d_name) >= (int)sizeof(path)) return 5;
        int child = open(path, O_PATH | O_CLOEXEC | O_NOFOLLOW);
        if (child < 0) return 6;
        struct stat st;
        if (fstat(child, &st) != 0) return 7;
        if (S_ISDIR(st.st_mode)) {
            struct landlock_path_beneath_attr rule = {
                .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE |
                                  LANDLOCK_ACCESS_FS_READ_FILE |
                                  LANDLOCK_ACCESS_FS_READ_DIR,
                .parent_fd = child,
            };
            if (syscall(SYS_landlock_add_rule, fd, LANDLOCK_RULE_PATH_BENEATH,
                        &rule, 0) != 0) return 8;
        }
        close(child);
    }
    closedir(root);
    int home = open("/sandbox", O_PATH | O_CLOEXEC);
    if (home < 0) return 12;
    struct landlock_path_beneath_attr home_rule = {
        .allowed_access = rights, .parent_fd = home,
    };
    if (syscall(SYS_landlock_add_rule, fd, LANDLOCK_RULE_PATH_BENEATH,
                &home_rule, 0) != 0) return 13;
    close(home);
    int devnull = open("/dev/null", O_PATH | O_CLOEXEC);
    if (devnull < 0) return 14;
    unsigned long long null_rights = LANDLOCK_ACCESS_FS_READ_FILE |
                                      LANDLOCK_ACCESS_FS_WRITE_FILE;
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
    null_rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
    struct landlock_path_beneath_attr null_rule = {
        .allowed_access = null_rights, .parent_fd = devnull,
    };
    if (syscall(SYS_landlock_add_rule, fd, LANDLOCK_RULE_PATH_BENEATH,
                &null_rule, 0) != 0) return 15;
    close(devnull);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 9;
    if (syscall(SYS_landlock_restrict_self, fd, 0) != 0) return 10;
    close(fd);
    execv(argv[1], argv + 1);
    return 11;
}
