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
 * STATUS (P2-17): Phase 2 stub — no call sites exist yet.  This file is
 * compiled into STANDARD/EDGE profiles (via DCLAW_MQTT_ENABLED) as a
 * placeholder for the future mTLS implementation.  The functions below
 * will be called from mqtt_client.c once TLS transport is wired in.
 */

int dclaw_tls_init(void) { return -1; }
void dclaw_tls_shutdown(void) {}
