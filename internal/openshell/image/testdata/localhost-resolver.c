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
#include <unistd.h>

int main(void) {
    alarm(5);
    struct addrinfo hints = {0}, *answers = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    // Prefer the IPv4 ingress address, then use IPv6 when the guest has no
    // IPv4 answer. Both calls use the completed image's own libc and NSS.
    if (getaddrinfo("localhost", NULL, &hints, &answers) != 0 || answers == NULL) {
        if (answers != NULL) freeaddrinfo(answers);
        answers = NULL;
        hints.ai_family = AF_INET6;
        if (getaddrinfo("localhost", NULL, &hints, &answers) != 0 || answers == NULL) return 1;
    }
    int count = 0, good = 1;
    for (struct addrinfo *p = answers; p != NULL; p = p->ai_next) {
        if (p->ai_family != hints.ai_family || p->ai_addr == NULL || ++count > 64 ||
            (p->ai_family == AF_INET && p->ai_addrlen < sizeof(struct sockaddr_in)) ||
            (p->ai_family == AF_INET6 && p->ai_addrlen < sizeof(struct sockaddr_in6))) {
            good = 0;
            break;
        }
        char address[INET6_ADDRSTRLEN];
        const void *raw = p->ai_family == AF_INET
            ? (const void *)&((struct sockaddr_in *)p->ai_addr)->sin_addr
            : (const void *)&((struct sockaddr_in6 *)p->ai_addr)->sin6_addr;
        if (inet_ntop(p->ai_family, raw, address, sizeof address) == NULL ||
            printf("%s STREAM\n", address) < 0) {
            good = 0;
            break;
        }
    }
    freeaddrinfo(answers);
    return good && count > 0 ? 0 : 1;
}
