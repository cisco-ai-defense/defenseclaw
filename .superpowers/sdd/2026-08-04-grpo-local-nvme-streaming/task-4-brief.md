## Task 4: Stream Engine (O_DIRECT Layer-by-Layer Forward)

**Files:**
- Modify: `internal/training/grpo_engine/stream.c` (replace stub)

**Interfaces:**
- Consumes: `GgufFile` from Task 1, kernels from Task 2
- Produces: `stream_open()`, `stream_forward_logprobs()`, `stream_close()`

- [ ] **Step 1: Implement O_DIRECT file opening with platform fallback**

```c
/* stream.c — layer-by-layer streaming forward pass for frozen models */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "grpo.h"

typedef struct {
    GgufFile gf;
    int      fd;           /* O_DIRECT fd (or regular fd on macOS) */
    void    *layer_buf;    /* aligned buffer for one layer's weights */
    size_t   layer_buf_sz; /* size of largest layer */
    int      use_direct;
} StreamEngine;

static int stream_open_file(StreamEngine *se, const char *path, int use_direct) {
    int flags = O_RDONLY;
#ifdef __linux__
    if (use_direct) flags |= O_DIRECT;
#endif
    se->fd = open(path, flags);
    if (se->fd < 0) {
        /* Fallback: try without O_DIRECT */
        se->fd = open(path, O_RDONLY);
        se->use_direct = 0;
    } else {
        se->use_direct = use_direct;
    }
#ifdef __APPLE__
    if (se->fd >= 0 && use_direct)
        fcntl(se->fd, F_NOCACHE, 1);
#endif
    return (se->fd >= 0) ? 0 : -1;
}
```

- [ ] **Step 2: Implement layer-by-layer forward pass**

```c
int stream_forward_logprobs(StreamEngine *se, const int *tokens, int len,
                            float *logprobs_out) {
    /* Allocate hidden state for full sequence */
    int hidden_dim = (int)se->gf.hidden_dim;
    float *hidden = (float *)calloc(len * hidden_dim, sizeof(float));

    /* Embed tokens */
    /* ... (lookup embedding table — can be streamed or mmap'd separately) ... */

    /* Process each layer: read from disk, compute, discard weights */
    for (int l = 0; l < se->gf.n_layers; l++) {
        /* Read this layer's weights into layer_buf via pread */
        /* layer_offset and layer_size are pre-computed from GGUF tensor table */
        ssize_t got = pread(se->fd, se->layer_buf, se->layer_sizes[l], se->layer_offsets[l]);
        if (got != (ssize_t)se->layer_sizes[l]) {
            free(hidden);
            return -1;
        }

        /* Apply transformer layer using weights in layer_buf */
        apply_stream_layer(se, hidden, len, l);
        /* layer_buf is now free to be overwritten by next layer */
    }

    /* Apply final norm + output head → logits → logprobs */
    /* ... compute logprobs per token ... */

    free(hidden);
    return 0;
}
```

- [ ] **Step 3: Pre-compute layer offset table from GGUF tensor map**

For each layer, determine which tensors belong to it and their combined byte range in the file. Store as `layer_offsets[]` and `layer_sizes[]`.

- [ ] **Step 4: Implement aligned buffer allocation**

```c
static void *alloc_aligned(size_t size, size_t align) {
    void *ptr = NULL;
    if (posix_memalign(&ptr, align, size) != 0) return NULL;
    return ptr;
}

/* layer_buf must be 4096-aligned for O_DIRECT */
se->layer_buf = alloc_aligned(se->layer_buf_sz, 4096);
```

- [ ] **Step 5: Build and verify**

Run: `make -C internal/training/grpo_engine`
Expected: Compiles. Functional testing requires a real GGUF file (deferred to integration tests).

- [ ] **Step 6: Commit**

```bash
git add internal/training/grpo_engine/stream.c
git commit -m "feat(training): implement NVMe streaming engine with O_DIRECT layer-by-layer forward"
```

---

