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
#include "platform.h"
#include <string.h>

#include "policy_tables.h"

extern dclaw_state_t *dclaw_get_state(void);

#define SESSION_TTL_MS (3600ULL * 1000)

static dclaw_session_t *find_session(uint16_t session_id) {
    dclaw_state_t *s = dclaw_get_state();
    uint64_t now = hal_tick_ms();
    for (int i = 0; i < DCLAW_MAX_SESSIONS; i++) {
        if (s->sessions[i].session_id == session_id && s->sessions[i].started_at != 0) {
            if (now - s->sessions[i].last_activity > SESSION_TTL_MS) {
                memset(&s->sessions[i], 0, sizeof(dclaw_session_t));
                return NULL;
            }
            return &s->sessions[i];
        }
    }
    return NULL;
}

static dclaw_session_t *create_session(uint16_t session_id) {
    dclaw_state_t *s = dclaw_get_state();
    /* Find empty slot or evict the oldest, preferring non-revoked sessions
     * so a burst of new session IDs cannot flush a revocation. */
    dclaw_session_t *oldest = NULL;
    for (int i = 0; i < DCLAW_MAX_SESSIONS; i++) {
        if (s->sessions[i].started_at == 0) {
            memset(&s->sessions[i], 0, sizeof(dclaw_session_t));
            s->sessions[i].session_id = session_id;
            s->sessions[i].started_at = hal_tick_ms();
            s->sessions[i].last_activity = s->sessions[i].started_at;
            return &s->sessions[i];
        }
        if (!oldest ||
            (oldest->revoked && !s->sessions[i].revoked) ||
            (oldest->revoked == s->sessions[i].revoked &&
             s->sessions[i].last_activity < oldest->last_activity)) {
            oldest = &s->sessions[i];
        }
    }
    /* Evict oldest session */
    memset(oldest, 0, sizeof(dclaw_session_t));
    oldest->session_id = session_id;
    oldest->started_at = hal_tick_ms();
    oldest->last_activity = oldest->started_at;
    return oldest;
}

void dclaw_session_revoke(uint16_t session_id) {
    dclaw_session_t *sess = find_session(session_id);
    if (!sess) sess = create_session(session_id);
    sess->revoked = true;
    sess->last_activity = hal_tick_ms();
}

bool dclaw_session_is_revoked(uint16_t session_id) {
    dclaw_session_t *sess = find_session(session_id);
    if (!sess || !sess->revoked) return false;
    /* Continued attempts keep the revocation alive. */
    sess->last_activity = hal_tick_ms();
    return true;
}

/* Clear correlator state for REVOKE_SESSIONS. Revoked sessions stay
 * revoked, and sessions with an unverified speculative call in flight are
 * revoked too: the reset discards the slots that would have checked them. */
void dclaw_sessions_reset_keep_revoked(void) {
    dclaw_state_t *s = dclaw_get_state();
    for (int i = 0; i < DCLAW_SPECULATIVE_SLOTS; i++) {
        if (s->speculative[i].request_id != 0) {
            dclaw_session_revoke(s->speculative[i].session_id);
        }
    }
    memset(s->speculative, 0, sizeof(s->speculative));

    for (int i = 0; i < DCLAW_MAX_SESSIONS; i++) {
        dclaw_session_t *sess = &s->sessions[i];
        if (sess->started_at != 0 && sess->revoked) {
            uint16_t id = sess->session_id;
            uint64_t started = sess->started_at;
            memset(sess, 0, sizeof(*sess));
            sess->session_id = id;
            sess->started_at = started;
            sess->last_activity = hal_tick_ms();
            sess->revoked = true;
        } else {
            memset(sess, 0, sizeof(*sess));
        }
    }
}

static bool match_sequence(const dclaw_session_t *sess, const dclaw_sequence_rule_t *rule) {
    if (sess->cap_count < rule->seq_len) return false;

    /* Check if the last N capabilities match the rule sequence */
    for (uint8_t i = 0; i < rule->seq_len; i++) {
        uint8_t idx = (sess->cap_head - rule->seq_len + i + DCLAW_SESSION_HISTORY_DEPTH)
                      % DCLAW_SESSION_HISTORY_DEPTH;
        if (sess->cap_history[idx] != rule->seq[i]) return false;
    }
    return true;
}

/*
 * Restrictiveness rank for combining matched rules. The enum values are wire
 * codes, not an ordering (BLOCK=1 < WARN=2 < ESCALATE=3), so comparing them
 * directly would let a co-matching WARN or ESCALATE rule downgrade a BLOCK.
 * Unknown action bytes (e.g. from a malformed OTA bundle) rank as BLOCK.
 */
static int action_rank(uint8_t action) {
    switch (action) {
    case DCLAW_ACTION_ALLOW:    return 0;
    case DCLAW_ACTION_WARN:     return 1;
    case DCLAW_ACTION_ESCALATE: return 2;
    default:                    return 3; /* BLOCK and unknown: fail closed */
    }
}

static dclaw_action_t more_restrictive(dclaw_action_t cur, uint8_t candidate) {
    if (action_rank(candidate) <= action_rank((uint8_t)cur)) return cur;
    if (action_rank(candidate) == 3) return DCLAW_ACTION_BLOCK;
    return (dclaw_action_t)candidate;
}

/* *ota_caused is set when the result is BLOCK only because of a rule in the
 * OTA-loaded runtime table; compiled-in rules cannot be changed by a push and
 * must not count toward the canary. */
dclaw_action_t dclaw_correlator_evaluate_ex(uint16_t session_id, uint8_t cap_flags,
                                            bool *ota_caused) {
    dclaw_session_t *sess = find_session(session_id);
    if (!sess) {
        sess = create_session(session_id);
    }

    /* Record this capability in history */
    sess->cap_history[sess->cap_head] = cap_flags;
    sess->cap_head = (sess->cap_head + 1) % DCLAW_SESSION_HISTORY_DEPTH;
    if (sess->cap_count < DCLAW_SESSION_HISTORY_DEPTH) sess->cap_count++;
    sess->last_activity = hal_tick_ms();

    /* Check compiled-in sequence rules */
    dclaw_action_t worst = DCLAW_ACTION_ALLOW;
    for (size_t i = 0; i < sequence_rules_count; i++) {
        if (match_sequence(sess, &sequence_rules[i])) {
            worst = more_restrictive(worst, sequence_rules[i].action);
        }
    }

    dclaw_action_t compiled_worst = worst;
    dclaw_state_t *st = dclaw_get_state();
    dclaw_policy_table_t *rt = &st->rt_policy;
    for (size_t i = 0; i < rt->sequence_rules_count; i++) {
        dclaw_sequence_rule_t rule_buf;
        memcpy(&rule_buf, &rt->sequence_rules[i], sizeof(rule_buf));
        const dclaw_sequence_rule_t *rule = &rule_buf;
        if (match_sequence(sess, rule)) {
            worst = more_restrictive(worst, rule->action);
        }
    }

    if (ota_caused)
        *ota_caused = rt->loaded && worst == DCLAW_ACTION_BLOCK &&
                      compiled_worst != DCLAW_ACTION_BLOCK;
    return worst;
}

dclaw_action_t dclaw_correlator_evaluate(uint16_t session_id, uint8_t cap_flags) {
    return dclaw_correlator_evaluate_ex(session_id, cap_flags, NULL);
}
