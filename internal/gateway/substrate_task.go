// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
)

// The end of an unattended --task run, from the actor's relay (GAP-0273,
// GAP-0274). Nobody watches such a run, so the gateway writes a substrate
// audit row (INFO for a finish, which the alert views leave out; MEDIUM for
// a failure, HIGH for a run the relay ended) that names how it ended (finished, failed, or ended by the relay for
// making no progress, with the relay's reason) and marks the actor's
// activity with a task_end, on which the controller suspends the actor and
// frees its worker.
//
// The route takes the actor's verified JWT like every actor route, and the
// agent shares that token: it could post here itself. So the row says the
// actor reported it, and no report is dropped (GAP-0291): every one is
// audited, numbered per actor on this replica, and those after the first
// are marked as repeats, so ends the agent posted first cannot hide the
// relay's own. The actor listener's per-actor rate limit bounds the rows,
// as it bounds hook rows. Early ends cost the agent only its own worker
// (the controller suspends a task actor that stays quiet after its end).
// A relay-only credential is the root fix (tracked in GAP-0291).

const (
	// substrateTaskEndMaxActors bounds the per-actor report counts.
	substrateTaskEndMaxActors = 10000
	substrateTaskCauseMax     = 512
)

// substrateTaskEnds counts the end reports per actor UID.
type substrateTaskEnds struct {
	mu   sync.Mutex
	rows map[string]int
}

// next numbers uid's report: 1 for its first on this replica.
func (t *substrateTaskEnds) next(uid string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rows == nil || len(t.rows) >= substrateTaskEndMaxActors {
		t.rows = map[string]int{}
	}
	t.rows[uid]++
	return t.rows[uid]
}

// serveSubstrateRelayTask takes a task end: POST {"exit_code", "stalled",
// "cause", "duration_ms"} from a --task actor. 204 when taken; the relay
// stops retrying on any 4xx.
func (a *APIServer) serveSubstrateRelayTask(st *substrateState, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeSubstrateRefusal(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor, ok := substrateActorFrom(r.Context())
	if !ok {
		writeSubstrateRefusal(w, http.StatusUnauthorized, "missing_token")
		return
	}
	reg, ok := substrateRegistrationFrom(r.Context())
	if !ok || reg.TaskDigest == "" {
		writeSubstrateRefusal(w, http.StatusForbidden, "not_a_task")
		return
	}
	var in struct {
		ExitCode   int    `json:"exit_code"`
		Stalled    bool   `json:"stalled"`
		Cause      string `json:"cause"`
		DurationMS int64  `json:"duration_ms"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in); err != nil {
		writeSubstrateRefusal(w, http.StatusBadRequest, "bad_report")
		return
	}
	if st.cfg.Activity != nil {
		st.cfg.Activity.ObserveActivity(SubstrateActivityTaskEnd, actor.Atespace, actor.UID, time.Now())
	}
	if st.alert != nil {
		n := st.taskEnds.next(actor.UID)
		severity, outcome := "INFO", "finished"
		switch {
		case in.Stalled:
			severity, outcome = "HIGH", "ended by the relay"
		case in.ExitCode != 0:
			severity, outcome = "MEDIUM", "failed"
		}
		took := (time.Duration(max(in.DurationMS, 0)) * time.Millisecond).Round(time.Second)
		summary := fmt.Sprintf("task %s: %s/%s exit %d after %s (reported by the actor)", outcome, actor.Atespace, actor.Name, in.ExitCode, took)
		cause := substrateReportText(in.Cause)
		if cause != "" {
			summary += "; " + cause
		}
		if n > 1 {
			summary = fmt.Sprintf("repeat %d: %s", n, summary)
		}
		st.alert(r.Context(), severity, summary, map[string]any{
			"event": "task_end", "atespace": actor.Atespace, "actor": actor.Name, "actor_uid": actor.UID,
			"batch_id": reg.BatchID, "exit_code": in.ExitCode, "stalled": in.Stalled, "cause": cause, "duration_ms": max(in.DurationMS, 0),
			"report": n, "repeat": n > 1,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// substrateReportText is an actor-sent reason fit for an audit row: one
// line of printable text, at most substrateTaskCauseMax runes.
func substrateReportText(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= substrateTaskCauseMax {
			break
		}
		if !unicode.IsPrint(r) {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}
