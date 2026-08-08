/* grpo_engine */
#include "bench_io.h"
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <model.gguf>\n", argv[0]);
        fprintf(stderr, "Runs O_DIRECT vs mmap comparison benchmark.\n");
        return 1;
    }

    /* Simple token sequence for benchmark (BOS + 32 tokens) */
    int tokens[33];
    for (int i = 0; i < 33; i++) tokens[i] = i + 1;

    StreamComparison cmp = stream_benchmark_comparison(argv[1], tokens, 33);
    stream_benchmark_print(&cmp);

    return 0;
}
