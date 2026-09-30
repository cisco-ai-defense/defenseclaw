#include "defenseclaw.h"
#include "platform.h"
#include <string.h>

#include "policy_tables.h"

extern dclaw_state_t *dclaw_get_state(void);

static dclaw_session_t *find_session(uint16_t session_id) {
    dclaw_state_t *s = dclaw_get_state();
    for (int i = 0; i < DCLAW_MAX_SESSIONS; i++) {
        if (s->sessions[i].session_id == session_id && s->sessions[i].started_at != 0) {
            return &s->sessions[i];
        }
    }
    return NULL;
}

static dclaw_session_t *create_session(uint16_t session_id) {
    dclaw_state_t *s = dclaw_get_state();
    /* Find empty slot or evict oldest */
    dclaw_session_t *oldest = &s->sessions[0];
    for (int i = 0; i < DCLAW_MAX_SESSIONS; i++) {
        if (s->sessions[i].started_at == 0) {
            memset(&s->sessions[i], 0, sizeof(dclaw_session_t));
            s->sessions[i].session_id = session_id;
            s->sessions[i].started_at = hal_tick_ms();
            s->sessions[i].last_activity = s->sessions[i].started_at;
            return &s->sessions[i];
        }
        if (s->sessions[i].last_activity < oldest->last_activity) {
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

dclaw_action_t dclaw_correlator_evaluate(uint16_t session_id, uint8_t cap_flags) {
    dclaw_session_t *sess = find_session(session_id);
    if (!sess) {
        sess = create_session(session_id);
    }

    /* Record this capability in history */
    sess->cap_history[sess->cap_head] = cap_flags;
    sess->cap_head = (sess->cap_head + 1) % DCLAW_SESSION_HISTORY_DEPTH;
    if (sess->cap_count < DCLAW_SESSION_HISTORY_DEPTH) sess->cap_count++;
    sess->last_activity = hal_tick_ms();

    /* Check all sequence rules */
    dclaw_action_t worst = DCLAW_ACTION_ALLOW;
    for (size_t i = 0; i < sequence_rules_count; i++) {
        if (match_sequence(sess, &sequence_rules[i])) {
            if (sequence_rules[i].action > worst) {
                worst = (dclaw_action_t)sequence_rules[i].action;
            }
        }
    }

    /* Accumulate risk */
    if (worst == DCLAW_ACTION_BLOCK) {
        sess->risk_score = (sess->risk_score > 200) ? 255 : sess->risk_score + 50;
    } else if (worst == DCLAW_ACTION_WARN) {
        sess->risk_score = (sess->risk_score > 240) ? 255 : sess->risk_score + 10;
    }

    return worst;
}
