#include "platform.h"

/*
 * TLS engine wrapper — STUB ONLY.
 *
 * TLS transport is NOT yet implemented. These functions always return
 * failure (-1) so that any code path that attempts to use TLS will
 * fail loudly rather than silently falling back to plaintext.
 *
 * Phase 2 will replace these stubs with an mbedTLS-backed
 * implementation for mTLS handshake + session management.
 */

int dclaw_tls_init(void) { return -1; }
void dclaw_tls_shutdown(void) {}
