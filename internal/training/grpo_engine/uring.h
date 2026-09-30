/* internal/training/grpo_engine/uring.h */
#ifndef GRPO_URING_H
#define GRPO_URING_H

#ifdef GRPO_HAS_URING

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct UringReader UringReader;

/* Open a file with an io_uring ring of given depth.
 * buf_align: alignment for read buffers (4096 for O_DIRECT). */
UringReader *uring_open(const char *path, int depth, size_t buf_align);

/* Close reader and free resources. */
void uring_close(UringReader *ur);

/* Submit an async read into buf at file offset. Returns 0 on success. */
int uring_submit_read(UringReader *ur, void *buf, size_t len, off_t offset);

/* Wait for the oldest submitted read to complete. Returns bytes read, or -1. */
int uring_wait_completion(UringReader *ur);

/* Runtime check: returns 1 if io_uring syscalls are available. */
int uring_available(void);

#else /* !GRPO_HAS_URING */

/* Stub: io_uring not available */
static inline int uring_available(void) { return 0; }

#endif /* GRPO_HAS_URING */
#endif /* GRPO_URING_H */
