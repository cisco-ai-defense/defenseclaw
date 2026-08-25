/* internal/training/grpo_engine/test_tokenizer.c */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tokenizer.h"

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); } \
    else { tests_passed++; } \
} while(0)

static void test_load(void) {
    GrpoTokenizer *tok = grpo_tokenizer_load("testdata/tokenizer_small.json");
    ASSERT(tok != NULL, "load tokenizer");
    ASSERT(grpo_tokenizer_vocab_size(tok) > 256, "vocab size > 256");
    grpo_tokenizer_free(tok);
}

static void test_encode_simple(void) {
    GrpoTokenizer *tok = grpo_tokenizer_load("testdata/tokenizer_small.json");
    ASSERT(tok != NULL, "load for encode");

    int ids[64];
    /* "hello" with merges: h+e=259(he), l+l=260(ll), then he+ll=264(hell), then o stays */
    int n = grpo_tokenizer_encode(tok, "hello", 5, ids, 64);
    ASSERT(n > 0, "encode returned tokens");
    /* After all merges: "hell" (264) + "o" (78) */
    ASSERT(n == 2, "hello encodes to 2 tokens");
    ASSERT(ids[0] == 264, "first token is 'hell'=264");
    ASSERT(ids[1] == 78, "second token is 'o'=78");

    grpo_tokenizer_free(tok);
}

static void test_decode_simple(void) {
    GrpoTokenizer *tok = grpo_tokenizer_load("testdata/tokenizer_small.json");
    ASSERT(tok != NULL, "load for decode");

    int ids[] = {264, 78};  /* "hell" + "o" = "hello" */
    char buf[256];
    int n = grpo_tokenizer_decode(tok, ids, 2, buf, 256);
    ASSERT(n == 5, "decode produced 5 bytes");
    ASSERT(strcmp(buf, "hello") == 0, "decoded to 'hello'");

    grpo_tokenizer_free(tok);
}

static void test_roundtrip(void) {
    GrpoTokenizer *tok = grpo_tokenizer_load("testdata/tokenizer_small.json");
    ASSERT(tok != NULL, "load for roundtrip");

    const char *text = "hello";
    int ids[64];
    int n = grpo_tokenizer_encode(tok, text, (int)strlen(text), ids, 64);
    ASSERT(n > 0, "encode succeeded");

    char buf[256];
    int m = grpo_tokenizer_decode(tok, ids, n, buf, 256);
    ASSERT(m == (int)strlen(text), "roundtrip length matches");
    ASSERT(strcmp(buf, text) == 0, "roundtrip text matches");

    grpo_tokenizer_free(tok);
}

int main(void) {
    test_load();
    test_encode_simple();
    test_decode_simple();
    test_roundtrip();
    printf("Tokenizer tests: %d/%d passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
