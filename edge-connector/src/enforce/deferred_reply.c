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

#include "defenseclaw.h"
#include "deferred_reply.h"
#include "platform.h"
#include <string.h>

extern dclaw_state_t *dclaw_get_state(void);
extern int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                             uint32_t target_hash, uint16_t session_id);

typedef struct {
    bool     active;
    int      fd;
    int32_t  rpc_id;
    uint16_t request_id;
    uint16_t session_id;
    uint32_t target_hash;
    uint64_t deadline_ms;
} deferred_t;

static deferred_t s_deferred[DCLAW_DEFERRED_MAX];
static dclaw_reply_writer_fn s_writer;

static dclaw_verdict_t block_verdict(dclaw_reason_t reason) {
    dclaw_verdict_t v = {
        .action = DCLAW_ACTION_BLOCK,
        .reason = reason,
        .severity = DCLAW_SEV_INFO,
        .mode = DCLAW_VERDICT_SYNC,
        .ttl_minutes = 0,
        .from_cache = false,
    };
    return v;
}

static void finish(deferred_t *d, const dclaw_verdict_t *v) {
    if (s_writer) (void)s_writer(d->fd, v, d->rpc_id);
    memset(d, 0, sizeof(*d));
}

void dclaw_deferred_init(dclaw_reply_writer_fn writer) {
    memset(s_deferred, 0, sizeof(s_deferred));
    s_writer = writer;
}

bool dclaw_deferred_add(int fd, int32_t rpc_id, uint16_t request_id,
                        uint16_t session_id, uint32_t target_hash, uint64_t now_ms) {
    if (request_id == 0) return false;
    for (int i = 0; i < DCLAW_DEFERRED_MAX; i++) {
        deferred_t *d = &s_deferred[i];
        if (d->active) continue;
        d->active = true;
        d->fd = fd;
        d->rpc_id = rpc_id;
        d->request_id = request_id;
        d->session_id = session_id;
        d->target_hash = target_hash;
        d->deadline_ms = now_ms + DCLAW_VERDICT_TIMEOUT_MS;
        return true;
    }
    return false;
}

bool dclaw_deferred_pending_for_fd(int fd) {
    for (int i = 0; i < DCLAW_DEFERRED_MAX; i++) {
        if (s_deferred[i].active && s_deferred[i].fd == fd) return true;
    }
    return false;
}

bool dclaw_deferred_any_pending(void) {
    for (int i = 0; i < DCLAW_DEFERRED_MAX; i++) {
        if (s_deferred[i].active) return true;
    }
    return false;
}

void dclaw_deferred_drop_fd(int fd) {
    for (int i = 0; i < DCLAW_DEFERRED_MAX; i++) {
        if (s_deferred[i].active && s_deferred[i].fd == fd) {
            memset(&s_deferred[i], 0, sizeof(s_deferred[i]));
        }
    }
}

void dclaw_deferred_resolve(uint16_t request_id, const dclaw_verdict_t *gateway) {
    if (request_id == 0 || !gateway) return;
    for (int i = 0; i < DCLAW_DEFERRED_MAX; i++) {
        deferred_t *d = &s_deferred[i];
        if (!d->active || d->request_id != request_id) continue;

        dclaw_verdict_t v = *gateway;
        v.mode = DCLAW_VERDICT_SYNC;
        v.from_cache = false;
        if (v.action != DCLAW_ACTION_BLOCK) {
            /* State may have changed while the call waited. */
            if (dclaw_get_state()->emergency.block_all_active) {
                v = block_verdict(DCLAW_REASON_CLOUD_BLOCK);
                dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_BLOCK,
                                  d->target_hash, d->session_id);
            } else if (dclaw_session_is_revoked(d->session_id)) {
                v = block_verdict(DCLAW_REASON_RETROACTIVE);
                dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_RETROACTIVE,
                                  d->target_hash, d->session_id);
            }
        }
        finish(d, &v);
        return;
    }
}

void dclaw_deferred_expire(uint64_t now_ms) {
    for (int i = 0; i < DCLAW_DEFERRED_MAX; i++) {
        deferred_t *d = &s_deferred[i];
        if (!d->active || now_ms < d->deadline_ms) continue;
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_TIMEOUT,
                          d->target_hash, d->session_id);
        dclaw_verdict_t v = block_verdict(DCLAW_REASON_CLOUD_TIMEOUT);
        finish(d, &v);
    }
}
