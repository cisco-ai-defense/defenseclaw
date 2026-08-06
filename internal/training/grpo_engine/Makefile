# internal/training/grpo_engine/Makefile
CC       ?= cc
CFLAGS   = -O3 -std=c99 -ffp-contract=off -fPIC -Wall -Wextra
LDFLAGS  = -lm

# Platform detection
UNAME_S := $(shell uname -s)

# OpenMP support
ifeq ($(UNAME_S),Darwin)
  # macOS: use Homebrew libomp
  LIBOMP_PREFIX := $(shell brew --prefix libomp 2>/dev/null)
  ifneq ($(LIBOMP_PREFIX),)
    CFLAGS  += -Xpreprocessor -fopenmp -I$(LIBOMP_PREFIX)/include
    LDFLAGS += -L$(LIBOMP_PREFIX)/lib -lomp
  endif
else
  # Linux: standard -fopenmp
  OPENMP_OK := $(shell echo "int main(){return 0;}" | $(CC) -x c -fopenmp - -o /dev/null 2>/dev/null && echo 1)
  ifeq ($(OPENMP_OK),1)
    CFLAGS  += -fopenmp
    LDFLAGS += -lgomp
  endif
endif

# AVX2: detect (x86 only)
AVX2_OK := $(shell $(CC) -mavx2 -mfma -dM -E - < /dev/null 2>/dev/null | grep -c AVX2)
ifeq ($(AVX2_OK),1)
  CFLAGS += -mavx2 -mfma
endif

SRCS = gguf.c kernels.c policy.c stream.c lora.c grpo.c tokenizer.c bench_io.c

# io_uring detection (Linux only)
ifeq ($(UNAME_S),Linux)
  URING_OK := $(shell echo '\#include <liburing.h>\nint main(){return 0;}' | $(CC) -x c - -luring -o /dev/null 2>/dev/null && echo 1)
  ifeq ($(URING_OK),1)
    SRCS += uring.c
    CFLAGS += -DGRPO_HAS_URING
    LDFLAGS += -luring
  endif
endif

OBJS = $(SRCS:.c=.o)

.PHONY: all clean test portable

all: libgrpo_stream.a

libgrpo_stream.a: $(OBJS)
	ar rcs $@ $^

%.o: %.c grpo.h
	$(CC) $(CFLAGS) -c $< -o $@

# kernels.c at -O1: clang's -O2+ auto-vectorizer generates unaligned NEON loads
# on mmap'd Q4_K data causing SIGBUS on macOS ARM. Force -O1 for this file only.
kernels.o: kernels.c grpo.h
	$(CC) -O1 -std=c99 -ffp-contract=off -fPIC -Wall -Wextra -c $< -o $@

portable:
	$(MAKE) CFLAGS="-O2 -std=c99 -ffp-contract=off -fPIC -Wall"

test: libgrpo_stream.a test_kernels.c
	$(CC) $(CFLAGS) test_kernels.c -L. -lgrpo_stream $(LDFLAGS) -o test_runner
	./test_runner

test_tokenizer: libgrpo_stream.a test_tokenizer.c
	$(CC) $(CFLAGS) -I. test_tokenizer.c -L. -lgrpo_stream $(LDFLAGS) -o test_tokenizer
	./test_tokenizer

bench_io: libgrpo_stream.a test_bench_io.c
	$(CC) $(CFLAGS) -I. test_bench_io.c -L. -lgrpo_stream $(LDFLAGS) -o bench_io

clean:
	rm -f *.o *.a test_runner test_tokenizer bench_io
