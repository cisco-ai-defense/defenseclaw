/* internal/training/grpo_engine/bench_io.c */
#ifndef __APPLE__
#define _POSIX_C_SOURCE 200809L
#endif
#include "bench_io.h"
#include "grpo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>

/* Forward declarations from stream.c */
struct StreamEngine;
struct StreamEngine *stream_open(const char *gguf_path, int use_direct_io);
int stream_forward_logprobs(struct StreamEngine *se, const int *tokens, int len, float *logprobs_out);
void stream_close(struct StreamEngine *se);

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t get_peak_rss_kb(void) {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
#ifdef __APPLE__
    return (uint64_t)usage.ru_maxrss / 1024;  /* macOS reports bytes */
#else
    return (uint64_t)usage.ru_maxrss;  /* Linux reports KB */
#endif
}

static StreamBenchStats run_mode(const char *path, int use_direct, const int *tokens, int len) {
    StreamBenchStats stats = {0};
    stats.mode = use_direct ? 0 : 1;

    uint64_t rss_before = get_peak_rss_kb();
    uint64_t t0 = now_ns();

    struct StreamEngine *se = stream_open(path, use_direct);
    if (!se) {
        fprintf(stderr, "bench_io: failed to open %s (mode=%d)\n", path, use_direct);
        return stats;
    }

    float *logprobs = (float *)calloc((size_t)len, sizeof(float));
    int ret = stream_forward_logprobs(se, tokens, len, logprobs);
    (void)ret;

    uint64_t t1 = now_ns();
    uint64_t rss_after = get_peak_rss_kb();

    stats.read_ns = t1 - t0;
    stats.peak_rss_kb = rss_after > rss_before ? rss_after - rss_before : rss_after;
    stats.num_layers = 28;  /* TODO: read from gguf metadata */

    /* Estimate bytes read (all layer weights processed) */
    /* Rough: file_size - embedding_size ≈ bytes streamed through layers */
    struct stat st;
    if (stat(path, &st) == 0) {
        stats.bytes_read = (uint64_t)st.st_size;
    }

    double elapsed_s = (double)stats.read_ns / 1e9;
    stats.throughput_gbps = elapsed_s > 0 ? ((double)stats.bytes_read / 1e9) / elapsed_s : 0;

    stream_close(se);
    free(logprobs);
    return stats;
}

StreamComparison stream_benchmark_comparison(const char *gguf_path,
                                            const int *tokens, int len) {
    StreamComparison cmp = {0};

    fprintf(stderr, "[bench_io] Running O_DIRECT mode...\n");
    cmp.direct = run_mode(gguf_path, 1, tokens, len);

    fprintf(stderr, "[bench_io] Running mmap mode...\n");
    cmp.mmap_full = run_mode(gguf_path, 0, tokens, len);

    cmp.rss_savings_kb = (int64_t)cmp.mmap_full.peak_rss_kb - (int64_t)cmp.direct.peak_rss_kb;
    cmp.throughput_ratio = cmp.mmap_full.throughput_gbps > 0
        ? cmp.direct.throughput_gbps / cmp.mmap_full.throughput_gbps
        : 0;

    return cmp;
}

void stream_benchmark_print(const StreamComparison *cmp) {
    fprintf(stderr, "\n┌─────────────┬──────────────┬──────────────┬──────────────┐\n");
    fprintf(stderr, "│ Mode        │ Throughput   │ Peak RSS     │ Time         │\n");
    fprintf(stderr, "├─────────────┼──────────────┼──────────────┼──────────────┤\n");
    fprintf(stderr, "│ O_DIRECT    │ %7.2f GB/s │ %8lu KB  │ %8.1f ms  │\n",
            cmp->direct.throughput_gbps, (unsigned long)cmp->direct.peak_rss_kb,
            (double)cmp->direct.read_ns / 1e6);
    fprintf(stderr, "│ mmap        │ %7.2f GB/s │ %8lu KB  │ %8.1f ms  │\n",
            cmp->mmap_full.throughput_gbps, (unsigned long)cmp->mmap_full.peak_rss_kb,
            (double)cmp->mmap_full.read_ns / 1e6);
    fprintf(stderr, "├─────────────┼──────────────┼──────────────┼──────────────┤\n");
    fprintf(stderr, "│ Savings     │ %+.0f%%         │ %+ld KB     │ %+.1f%%        │\n",
            (cmp->throughput_ratio - 1.0) * 100,
            (long)cmp->rss_savings_kb,
            cmp->direct.read_ns > 0
              ? ((double)cmp->mmap_full.read_ns - (double)cmp->direct.read_ns) / (double)cmp->direct.read_ns * 100
              : 0.0);
    fprintf(stderr, "└─────────────┴──────────────┴──────────────┴──────────────┘\n");
}
