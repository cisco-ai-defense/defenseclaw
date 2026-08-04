# internal/training/grpo_engine/Makefile
CC       ?= gcc
CFLAGS   = -O3 -std=c99 -ffp-contract=off -fPIC -Wall -Wextra
LDFLAGS  = -lm

# OpenMP: detect availability
OPENMP_OK := $(shell echo "int main(){return 0;}" | $(CC) -x c -fopenmp - -o /dev/null 2>/dev/null && echo 1)
ifeq ($(OPENMP_OK),1)
  CFLAGS += -fopenmp
  LDFLAGS += -lgomp
endif

# AVX2: detect availability
AVX2_OK := $(shell $(CC) -mavx2 -mfma -dM -E - < /dev/null 2>/dev/null | grep -c AVX2)
ifeq ($(AVX2_OK),1)
  CFLAGS += -mavx2 -mfma
endif

SRCS = gguf.c kernels.c policy.c stream.c lora.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean test portable

all: libgrpo_stream.a

libgrpo_stream.a: $(OBJS)
	ar rcs $@ $^

%.o: %.c grpo.h
	$(CC) $(CFLAGS) -c $< -o $@

portable:
	$(MAKE) CFLAGS="-O2 -std=c99 -ffp-contract=off -fPIC -Wall"

test: libgrpo_stream.a test_kernels.c
	$(CC) $(CFLAGS) test_kernels.c -L. -lgrpo_stream $(LDFLAGS) -o test_runner
	./test_runner

clean:
	rm -f *.o *.a test_runner
