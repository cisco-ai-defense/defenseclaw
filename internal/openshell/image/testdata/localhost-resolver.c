// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// DefenseClaw's MicroVM localhost check. It resolves localhost with the
// image's own libc, the way every program in the guest does, and passes only
// when every answer of every address family is loopback.
//
// Only libc's own code may answer: the image's hosts sources must be the
// files and dns sources built into libc, and no other object may be mapped
// into this process before or during the lookups. An NSS module or a preload
// is image code that can tell this program from any other and answer it
// alone with loopback, so no probe could show what the harness gets.
//
// Output, one line each: "<query> <address>" for each distinct answer of the
// unspec (AF_UNSPEC, what ordinary programs ask), inet and inet6 queries, then
// "loopback-only" and exit status 0. A refusal prints "refused <reason>" and
// exits 1: noanswer (the unspec query has no answer), nonloopback (some answer
// is not 127.0.0.1 or ::1), family (an answer of another family than asked),
// preload (code an image injects into every process) or nss (a hosts source
// besides files and dns in /etc/nsswitch.conf, or an object the lookups
// loaded).

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <link.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

struct loaded {
    int objects, libc, loader, vdso, other;
};

static const char *base_name(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash != NULL ? slash + 1 : path;
}

// Counts what the dynamic loader mapped into this process before main: the
// program, the vDSO, libc and the loader itself, and nothing else. Objects
// from /etc/ld.so.preload or LD_PRELOAD are mapped ahead of libc.
static int count_object(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct loaded *l = data;
    const char *name = info->dlpi_name != NULL ? info->dlpi_name : "";
    const char *base = base_name(name);
    if (l->objects++ == 0) {
        return 0;
    }
    if (strcmp(base, "libc.so.6") == 0) {
        l->libc++;
    } else if (strncmp(base, "ld-linux", 8) == 0 && strstr(base, ".so.") != NULL) {
        l->loader++;
    } else if (strchr(name, '/') == NULL &&
               (name[0] == 0 || strncmp(name, "linux-vdso", 10) == 0 || strncmp(name, "linux-gate", 10) == 0)) {
        l->vdso++;
    } else {
        l->other++;
    }
    return 0;
}

static int preloaded(struct loaded *l) {
    dl_iterate_phdr(count_object, l);
    return l->other != 0 || l->libc > 1 || l->loader > 1 || l->vdso > 1;
}

// hosts_sources_builtin reports whether every hosts line of nsswitch.conf
// names only the files and dns sources (with any [status=action] items).
// A missing file is glibc's default, which uses only those two. Every line
// whose database is hosts in any letter case counts, and only one may exist.
static int hosts_sources_builtin(void) {
    FILE *f = fopen("/etc/nsswitch.conf", "re");
    if (f == NULL) return errno == ENOENT;
    char line[4096];
    int hosts = 0, good = 1;
    while (good && fgets(line, sizeof line, f) != NULL) {
        size_t n = strlen(line);
        if (n == sizeof line - 1 && line[n - 1] != '\n') {
            good = 0;
            break;
        }
        char *hash = strchr(line, '#');
        if (hash != NULL) *hash = 0;
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        char *key = p;
        while (*p != 0 && *p != ':' && !isspace((unsigned char)*p)) p++;
        size_t keylen = (size_t)(p - key);
        while (isspace((unsigned char)*p)) p++;
        if (*p != ':' || keylen != 5 || strncasecmp(key, "hosts", 5) != 0) continue;
        if (hosts++) {
            good = 0;
            break;
        }
        p++;
        for (;;) {
            while (isspace((unsigned char)*p)) p++;
            if (*p == 0) break;
            if (*p == '[') {
                char *end = strchr(p, ']');
                if (end == NULL) {
                    good = 0;
                    break;
                }
                for (char *c = p + 1; c < end; c++) {
                    if (!isalpha((unsigned char)*c) && *c != '=' && *c != '!' && !isspace((unsigned char)*c)) good = 0;
                }
                p = end + 1;
                continue;
            }
            char *word = p;
            while (*p != 0 && !isspace((unsigned char)*p) && *p != '[') p++;
            size_t len = (size_t)(p - word);
            if (!((len == 5 && strncmp(word, "files", 5) == 0) || (len == 3 && strncmp(word, "dns", 3) == 0))) {
                good = 0;
                break;
            }
        }
    }
    if (ferror(f)) good = 0;
    fclose(f);
    return good;
}

static const char *refusal;

static void refuse(const char *reason) {
    if (refusal == NULL) refusal = reason;
}

// query resolves localhost for family and prints each distinct loopback
// answer. It returns the number of answers.
static int query(int family, const char *tag) {
    struct addrinfo hints = {0}, *answers = NULL;
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("localhost", NULL, &hints, &answers) != 0) {
        return 0;
    }
    int count = 0, v4 = 0, v6 = 0;
    for (struct addrinfo *p = answers; p != NULL; p = p->ai_next) {
        count++;
        if (p->ai_addr == NULL || (family != AF_UNSPEC && p->ai_family != family)) {
            refuse("family");
        } else if (p->ai_family == AF_INET && p->ai_addrlen >= sizeof(struct sockaddr_in) &&
                   p->ai_addr->sa_family == AF_INET) {
            if (((struct sockaddr_in *)p->ai_addr)->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
                refuse("nonloopback");
            } else if (!v4++) {
                printf("%s 127.0.0.1\n", tag);
            }
        } else if (p->ai_family == AF_INET6 && p->ai_addrlen >= sizeof(struct sockaddr_in6) &&
                   p->ai_addr->sa_family == AF_INET6) {
            if (!IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)p->ai_addr)->sin6_addr)) {
                refuse("nonloopback");
            } else if (!v6++) {
                printf("%s ::1\n", tag);
            }
        } else {
            refuse("family");
        }
    }
    freeaddrinfo(answers);
    return count;
}

int main(void) {
    alarm(5);
    struct loaded before = {0}, after = {0};
    if (preloaded(&before)) {
        printf("refused preload\n");
        return 1;
    }
    if (!hosts_sources_builtin()) {
        printf("refused nss\n");
        return 1;
    }
    // A family the image does not map may fail on its own; the unspec query,
    // what programs ask by default, must have an answer.
    if (query(AF_UNSPEC, "unspec") == 0) refuse("noanswer");
    query(AF_INET, "inet");
    query(AF_INET6, "inet6");
    // Whatever the lookups mapped (an NSS module) answered them, not libc.
    dl_iterate_phdr(count_object, &after);
    if (after.objects != before.objects) {
        refusal = "nss";
    }
    if (refusal != NULL) {
        printf("refused %s\n", refusal);
        return 1;
    }
    if (printf("loopback-only\n") < 0 || fflush(stdout) != 0) return 1;
    return 0;
}
