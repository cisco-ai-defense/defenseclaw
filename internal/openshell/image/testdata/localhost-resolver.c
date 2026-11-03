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

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOSTS_LIMIT (1 << 20)

static int localhost_alias(const char *s) {
    const char *name = "localhost";
    for (; *s && *name; s++, name++) {
        unsigned char c = (unsigned char)*s;
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != (unsigned char)*name) return 0;
    }
    return *s == 0 && *name == 0;
}

// The file check distinguishes an IPv6-only localhost entry from an IPv4
// entry. libc can otherwise synthesize an IPv4 answer from ::1. Other file
// syntax is decided by the resolver below.
static int hosts_file_valid(void) {
    FILE *f = fopen("/etc/hosts", "rb");
    if (f == NULL) return 0;
    char *data = malloc(HOSTS_LIMIT + 2);
    if (data == NULL) { fclose(f); return 0; }
    size_t n = fread(data, 1, HOSTS_LIMIT + 1, f);
    int good = !ferror(f) && n <= HOSTS_LIMIT;
    fclose(f);
    if (!good) { free(data); return 0; }
    data[n] = 0;
    int named_v6 = 0, named_v4 = 0;
    for (char *line = data; line < data + n;) {
        char *end = memchr(line, '\n', (size_t)(data + n - line));
        if (end == NULL) end = data + n;
        else *end = 0;
        if (end > line && end[-1] == '\r') end[-1] = 0;

        char *save = NULL;
        char *address = strtok_r(line, " \t\v\f\r", &save);
        if (address != NULL && address[0] != '#') {
            unsigned char parsed[sizeof(struct in6_addr)];
            int is_v4 = inet_pton(AF_INET, address, parsed) == 1;
            int is_v6 = inet_pton(AF_INET6, address, parsed) == 1;
            for (char *alias = strtok_r(NULL, " \t\v\f\r", &save); alias != NULL;
                 alias = strtok_r(NULL, " \t\v\f\r", &save)) {
                if (alias[0] == '#') break;
                if (localhost_alias(alias)) {
                    named_v4 |= is_v4;
                    named_v6 |= is_v6;
                }
            }
        }
        line = end == data + n ? data + n : end + 1;
    }
    free(data);
    return !(named_v6 && !named_v4);
}

int main(void) {
    if (!hosts_file_valid()) return 1;
    struct addrinfo hints = {0}, *answers = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("localhost", NULL, &hints, &answers) != 0 || answers == NULL) return 1;
    int count = 0, good = 1;
    for (struct addrinfo *p = answers; p != NULL; p = p->ai_next) {
        if (p->ai_family != AF_INET || p->ai_addrlen < sizeof(struct sockaddr_in) || ++count > 64) {
            good = 0;
            break;
        }
        char address[INET_ADDRSTRLEN];
        struct sockaddr_in *a = (struct sockaddr_in *)p->ai_addr;
        if (inet_ntop(AF_INET, &a->sin_addr, address, sizeof address) == NULL ||
            printf("%s STREAM\n", address) < 0) {
            good = 0;
            break;
        }
    }
    freeaddrinfo(answers);
    return good && count > 0 ? 0 : 1;
}
