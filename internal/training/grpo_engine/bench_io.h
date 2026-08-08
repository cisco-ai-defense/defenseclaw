/* grpo_engine */
#ifndef GRPO_BENCH_IO_H
#define GRPO_BENCH_IO_H

#include <stdint.h>

typedef struct {
    uint64_t bytes_read;
    uint64_t read_calls;
    uint64_t read_ns;
    uint64_t compute_ns;
    uint64_t peak_rss_kb;
    int      num_layers;
    int      mode;  /* 0=O_DIRECT, 1=mmap */
    double   throughput_gbps;
} StreamBenchStats;

typedef struct {
    StreamBenchStats direct;
    StreamBenchStats mmap_full;
    double throughput_ratio;
    int64_t rss_savings_kb;
} StreamComparison;

/* Run comparison: same logprob computation with both I/O modes.
 * tokens/len: input sequence for reference model forward pass. */
StreamComparison stream_benchmark_comparison(const char *gguf_path,
                                            const int *tokens, int len);

/* Print formatted comparison table to stderr */
void stream_benchmark_print(const StreamComparison *cmp);

#endif /* GRPO_BENCH_IO_H */
