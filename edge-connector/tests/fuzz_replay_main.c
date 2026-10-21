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


/* Runs a libFuzzer entry point over the files named on the command line,
 * for toolchains without the libFuzzer runtime and as a corpus smoke test. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) {
            fprintf(stderr, "cannot open %s\n", argv[i]);
            return 1;
        }
        uint8_t *buf = NULL;
        size_t len = 0, cap = 0;
        for (;;) {
            if (len == cap) {
                cap = cap ? cap * 2 : 4096;
                uint8_t *nb = realloc(buf, cap);
                if (!nb) { free(buf); fclose(f); return 1; }
                buf = nb;
            }
            size_t n = fread(buf + len, 1, cap - len, f);
            if (n == 0) break;
            len += n;
        }
        fclose(f);
        (void)LLVMFuzzerTestOneInput(buf, len);
        free(buf);
        printf("ran %s (%zu bytes)\n", argv[i], len);
    }
    return 0;
}
