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
// image's own libc and NSS modules, the way every program in the guest does,
// and passes only when every answer of every address family is loopback.
//
// Output, one line each: "<query> <address>" for each distinct answer of the
// unspec (AF_UNSPEC, what ordinary programs ask), inet and inet6 queries, then
// "loopback-only" and exit status 0. A refusal prints "refused <reason>" and
// exits 1: noanswer (the unspec query has no answer), nonloopback (some answer
// is not 127.0.0.1 or ::1), family (an answer of another family than asked)
// or preload (code an image injects into every process, for which no probe
// can show what other programs get).

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <link.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
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

static int preloaded(void) {
    struct loaded l = {0};
    dl_iterate_phdr(count_object, &l);
    return l.other != 0 || l.libc > 1 || l.loader > 1 || l.vdso > 1;
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
    if (preloaded()) {
        printf("refused preload\n");
        return 1;
    }
    // A family the image does not map may fail on its own; the unspec query,
    // what programs ask by default, must have an answer.
    if (query(AF_UNSPEC, "unspec") == 0) refuse("noanswer");
    query(AF_INET, "inet");
    query(AF_INET6, "inet6");
    if (refusal != NULL) {
        printf("refused %s\n", refusal);
        return 1;
    }
    if (printf("loopback-only\n") < 0 || fflush(stdout) != 0) return 1;
    return 0;
}
