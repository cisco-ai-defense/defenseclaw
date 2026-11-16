// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// A stand-in program for tests that prints its arguments. It works under any
// file name it is copied or linked to; see sleep.c.
#include <stdio.h>

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        printf("%s%s", i > 1 ? " " : "", argv[i]);
    }
    putchar(10);
    return 0;
}
