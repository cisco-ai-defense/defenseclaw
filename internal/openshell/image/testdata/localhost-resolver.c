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

static int alias_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

static int localhost_alias(const char *s) {
    const char *name = "localhost";
    for (; *s && *name; s++, name++) {
        unsigned char c = (unsigned char)*s;
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != (unsigned char)*name) return 0;
    }
    return *s == 0 && *name == 0;
}

// The file check applies to nonempty image hosts files. It keeps a
// localhost entry with only an IPv6 address from satisfying the IPv4 check.
static int hosts_file_valid(void) {
    FILE *f = fopen("/etc/hosts", "rb");
    if (f == NULL) return 0;
    char *data = malloc(HOSTS_LIMIT + 2);
    if (data == NULL) { fclose(f); return 0; }
    size_t n = fread(data, 1, HOSTS_LIMIT + 1, f);
    int good = !ferror(f) && n <= HOSTS_LIMIT;
    fclose(f);
    if (!good) { free(data); return 0; }

    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)data[i];
        if (c == 0 || (c < 32 && c != '\n' && c != '\r' && c != '\t') ||
            (c == '\r' && (i + 1 == n || data[i + 1] != '\n'))) {
            free(data);
            return 0;
        }
    }
    data[n] = 0;
    int named = 0, ipv4 = 0;
    for (char *line = data; line < data + n;) {
        char *end = strchr(line, '\n');
        if (end == NULL) end = data + n;
        else *end = 0;
        if (end > line && end[-1] == '\r') end[-1] = 0;

        char *save = NULL;
        char *address = strtok_r(line, " \t", &save);
        if (address != NULL && address[0] != '#') {
            unsigned char parsed[sizeof(struct in6_addr)];
            int family = inet_pton(AF_INET, address, parsed) == 1 ? AF_INET : AF_INET6;
            int valid_address = family == AF_INET || inet_pton(AF_INET6, address, parsed) == 1;
            if (strcmp(address, "include") == 0) good = 0;
            for (const unsigned char *p = (const unsigned char *)address; *p; p++) {
                if (*p > 127) good = 0;
            }
            int aliases = 0;
            for (char *alias = strtok_r(NULL, " \t", &save); alias != NULL;
                 alias = strtok_r(NULL, " \t", &save)) {
                if (alias[0] == '#') break;
                for (const unsigned char *p = (const unsigned char *)alias; *p; p++) {
                    if (!alias_char(*p)) good = 0;
                }
                if (localhost_alias(alias)) {
                    named = 1;
                    if (!valid_address) good = 0;
                    if (family == AF_INET) {
                        if (strcmp(address, "127.0.0.1") != 0) good = 0;
                        else ipv4 = 1;
                    }
                }
                aliases++;
            }
            if (aliases == 0 && valid_address) good = 0;
        }
        line = end == data + n ? data + n : end + 1;
    }
    free(data);
    return good && (!named || ipv4);
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
