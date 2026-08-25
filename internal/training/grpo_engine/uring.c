/* internal/training/grpo_engine/uring.c */
#ifdef GRPO_HAS_URING

#include "uring.h"
#include <liburing.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

struct UringReader {
    struct io_uring ring;
    int             fd;
    int             depth;
    int             pending;    /* number of submissions not yet completed */
    size_t          buf_align;
};

int uring_available(void) {
    /* Probe: try io_uring_setup with 0 entries to check kernel support */
    struct io_uring_params params = {0};
    int ret = (int)syscall(__NR_io_uring_setup, 1, &params);
    if (ret >= 0) {
        close(ret);
        return 1;
    }
    return 0;
}

UringReader *uring_open(const char *path, int depth, size_t buf_align) {
    if (!uring_available()) return NULL;

    UringReader *ur = (UringReader *)calloc(1, sizeof(UringReader));
    if (!ur) return NULL;

    ur->depth = depth > 0 ? depth : 2;
    ur->buf_align = buf_align > 0 ? buf_align : 4096;
    ur->pending = 0;

    /* Open file with O_DIRECT for aligned I/O */
    ur->fd = open(path, O_RDONLY | O_DIRECT);
    if (ur->fd < 0) {
        /* Fallback without O_DIRECT */
        ur->fd = open(path, O_RDONLY);
        if (ur->fd < 0) {
            free(ur);
            return NULL;
        }
    }

    /* Initialize io_uring */
    int ret = io_uring_queue_init((unsigned)ur->depth, &ur->ring, 0);
    if (ret < 0) {
        fprintf(stderr, "uring: queue_init failed: %s\n", strerror(-ret));
        close(ur->fd);
        free(ur);
        return NULL;
    }

    return ur;
}

void uring_close(UringReader *ur) {
    if (!ur) return;
    /* Drain pending completions */
    while (ur->pending > 0) {
        uring_wait_completion(ur);
    }
    io_uring_queue_exit(&ur->ring);
    close(ur->fd);
    free(ur);
}

int uring_submit_read(UringReader *ur, void *buf, size_t len, off_t offset) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ur->ring);
    if (!sqe) {
        /* Ring full — wait for one completion first */
        if (uring_wait_completion(ur) < 0) return -1;
        sqe = io_uring_get_sqe(&ur->ring);
        if (!sqe) return -1;
    }

    io_uring_prep_read(sqe, ur->fd, buf, (unsigned)len, offset);
    io_uring_sqe_set_data(sqe, buf);

    int ret = io_uring_submit(&ur->ring);
    if (ret < 0) {
        fprintf(stderr, "uring: submit failed: %s\n", strerror(-ret));
        return -1;
    }

    ur->pending++;
    return 0;
}

int uring_wait_completion(UringReader *ur) {
    if (ur->pending <= 0) return 0;

    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(&ur->ring, &cqe);
    if (ret < 0) {
        fprintf(stderr, "uring: wait_cqe failed: %s\n", strerror(-ret));
        return -1;
    }

    int bytes = cqe->res;
    if (bytes < 0) {
        fprintf(stderr, "uring: read failed: %s\n", strerror(-bytes));
        bytes = -1;
    }

    io_uring_cqe_seen(&ur->ring, cqe);
    ur->pending--;
    return bytes;
}

#endif /* GRPO_HAS_URING */
