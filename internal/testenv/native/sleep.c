// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// A stand-in long-running program for tests. It sleeps for its first
// argument (seconds, fractions allowed) and works under any file name it is
// copied or linked to: a distribution may ship its sleep(1) as one entry of a
// multi-call binary that refuses to run under another name (Ubuntu 26.04).
// nanosleep is POSIX: strict C (-std=c11) hides it without this.
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv) {
    double seconds = argc > 1 ? atof(argv[1]) : 1;
    struct timespec left = {(time_t)seconds, (long)((seconds - (double)(time_t)seconds) * 1e9)};
    while (nanosleep(&left, &left) == -1 && errno == EINTR) {
    }
    return 0;
}
