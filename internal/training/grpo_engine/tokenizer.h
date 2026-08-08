/* grpo_engine */
#ifndef GRPO_TOKENIZER_H
#define GRPO_TOKENIZER_H

#include <stddef.h>

typedef struct GrpoTokenizer GrpoTokenizer;

/* Load a HuggingFace tokenizer.json file. Returns NULL on failure. */
GrpoTokenizer *grpo_tokenizer_load(const char *path);

/* Load tokenizer vocabulary from a GGUF file's metadata (tokenizer.ggml.tokens).
 * This is the preferred method for GGUF models that embed their vocab. */
GrpoTokenizer *grpo_tokenizer_load_gguf(const char *gguf_path);

/* Free tokenizer resources. */
void grpo_tokenizer_free(GrpoTokenizer *tok);

/* Encode UTF-8 text to token IDs. Returns number of tokens written, or -1 on error. */
int grpo_tokenizer_encode(const GrpoTokenizer *tok, const char *text, int text_len,
                          int *output_ids, int max_tokens);

/* Decode token IDs to UTF-8 text. Returns bytes written (null-terminated), or -1 on error. */
int grpo_tokenizer_decode(const GrpoTokenizer *tok, const int *ids, int n_ids,
                          char *output_buf, int buf_size);

/* Return vocabulary size. */
int grpo_tokenizer_vocab_size(const GrpoTokenizer *tok);

#endif /* GRPO_TOKENIZER_H */
