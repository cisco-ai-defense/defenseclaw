#include "platform.h"

/*
 * TLS engine wrapper — STUB ONLY (P2-17 documented).
 *
 * TLS transport is NOT yet implemented. These functions always return
 * failure (-1) so that any code path that attempts to use TLS will
 * fail loudly rather than silently falling back to plaintext.
 *
 * Phase 2 will replace these stubs with an mbedTLS-backed
 * implementation for mTLS handshake + session management.
 *
 * STATUS: This file is intentionally compiled into STANDARD/EDGE profiles
 * (via DCLAW_MQTT_ENABLED) to satisfy linker references from mqtt_client.c.
 * The stubs are NOT dead code — they are required placeholders. When TLS
 * support is implemented, these will be replaced with real implementations.
 */

int dclaw_tls_init(void) { return -1; }
void dclaw_tls_shutdown(void) {}
