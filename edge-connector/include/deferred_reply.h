/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DCLAW_DEFERRED_REPLY_H
#define DCLAW_DEFERRED_REPLY_H

#include "defenseclaw.h"

/*
 * Deferred IPC replies for synchronous escalation.
 *
 * A call whose class may not run speculatively and that has no local or
 * cached decision is escalated to the gateway. Its IPC reply is held until
 * the gateway verdict arrives or DCLAW_VERDICT_TIMEOUT_MS elapses, in which
 * case the call is denied with CLOUD_TIMEOUT. While a reply is held, the
 * daemon stops reading from that client so replies stay in request order.
 */

#define DCLAW_DEFERRED_MAX 8

/* Writes one verdict reply to a client. Returns 0 on success. */
typedef int (*dclaw_reply_writer_fn)(int fd, const dclaw_verdict_t *v, int32_t rpc_id);

void dclaw_deferred_init(dclaw_reply_writer_fn writer);

/* Hold the reply for an escalated request. Returns false if the table is
 * full; the caller must then reply BLOCK itself. */
bool dclaw_deferred_add(int fd, int32_t rpc_id, uint16_t request_id,
                        uint16_t session_id, uint32_t target_hash, uint64_t now_ms);

bool dclaw_deferred_pending_for_fd(int fd);

/* True if any reply is held (the event loop must wake often enough to expire it). */
bool dclaw_deferred_any_pending(void);

/* Forget held replies for a client that disconnected. */
void dclaw_deferred_drop_fd(int fd);

/* Deliver a verified gateway verdict. Unknown request IDs are ignored. If an
 * emergency BLOCK_ALL became active or the session was revoked while
 * waiting, the reply is BLOCK regardless of the gateway verdict. */
void dclaw_deferred_resolve(uint16_t request_id, const dclaw_verdict_t *gateway);

/* Deny held replies whose deadline has passed. */
void dclaw_deferred_expire(uint64_t now_ms);

#endif /* DCLAW_DEFERRED_REPLY_H */
