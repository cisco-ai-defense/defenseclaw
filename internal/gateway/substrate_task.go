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
// actor reported it, and no report goes uncounted (GAP-0291): every one is
// numbered per actor on this replica and marks the actor's activity. Rows
// are collapsed per kind of end (severity, exit code, cause), so the agent
// cannot mint HIGH rows at the actor listener's 20 calls a second
// (GAP-0303): the first few reports of a kind are audited, as repeats, so
// ends the agent posted first cannot hide the relay's own; after that a
// row is written only when the count of the kind reaches a power of two
// (8, 16, 32, ...), and says how many repeats since the last row were not
// audited. At most substrateTaskEndMaxKinds kinds are tracked per actor;
// later ones share one kind per severity. Early ends cost the agent only
// its own worker (the controller suspends a task actor that stays quiet
// after its end). A relay-only credential is the root fix (tracked in
// GAP-0291).

const (
	// substrateTaskEndMaxActors bounds the per-actor report counts.
	substrateTaskEndMaxActors = 10000
	// substrateTaskEndMaxKinds bounds the distinct kinds of end counted per actor.
	substrateTaskEndMaxKinds = 16
	// substrateTaskEndPlainRows is how many reports of a kind are audited one by one.
	substrateTaskEndPlainRows = 3
	// substrateTaskEndFirstSummary is the first count of a kind, after the plain
	// rows, at which a row is written (then each power of two).
	substrateTaskEndFirstSummary = 8
	substrateTaskCauseMax        = 512
)

// substrateTaskEndCounts is one actor's report counts.
type substrateTaskEndCounts struct {
	total int
	kinds map[string]int
}

// substrateTaskEnds counts the end reports per actor UID.
type substrateTaskEnds struct {
	mu   sync.Mutex
	rows map[string]*substrateTaskEndCounts
}

// substrateTaskEndNumber says how a report is counted: its number among the
// actor's reports, its number among the reports of its kind, whether it is
// audited, and how many reports of its kind since the last audited row were not.
type substrateTaskEndNumber struct {
	total, count, unaudited int
	audit                   bool
}

// next numbers uid's report of the given kind (and of the coarse kind that
// stands in for it once the actor has substrateTaskEndMaxKinds kinds).
func (t *substrateTaskEnds) next(uid, kind, coarse string) substrateTaskEndNumber {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rows == nil || len(t.rows) >= substrateTaskEndMaxActors {
		t.rows = map[string]*substrateTaskEndCounts{}
	}
	c := t.rows[uid]
	if c == nil {
		c = &substrateTaskEndCounts{kinds: map[string]int{}}
		t.rows[uid] = c
	}
	if _, seen := c.kinds[kind]; !seen && len(c.kinds) >= substrateTaskEndMaxKinds {
		kind = coarse
	}
	c.total++
	c.kinds[kind]++
	n := c.kinds[kind]
	out := substrateTaskEndNumber{total: c.total, count: n}
	switch {
	case n <= substrateTaskEndPlainRows:
		out.audit = true
	case n >= substrateTaskEndFirstSummary && n&(n-1) == 0:
		out.audit = true
		written := substrateTaskEndPlainRows
		for p := substrateTaskEndFirstSummary; p < n; p *= 2 {
			written++
		}
		out.unaudited = n - 1 - written
	}
	return out
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
		severity, outcome := "INFO", "finished"
		switch {
		case in.Stalled:
			severity, outcome = "HIGH", "ended by the relay"
		case in.ExitCode != 0:
			severity, outcome = "MEDIUM", "failed"
		}
		cause := substrateReportText(in.Cause)
		num := st.taskEnds.next(actor.UID, fmt.Sprintf("%s|%d|%s", severity, in.ExitCode, cause), severity)
		if !num.audit {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		took := (time.Duration(max(in.DurationMS, 0)) * time.Millisecond).Round(time.Second)
		summary := fmt.Sprintf("task %s: %s/%s exit %d after %s (reported by the actor)", outcome, actor.Atespace, actor.Name, in.ExitCode, took)
		if cause != "" {
			summary += "; " + cause
		}
		if num.total > 1 {
			summary = fmt.Sprintf("repeat %d: %s", num.total, summary)
		}
		if num.unaudited > 0 {
			summary += fmt.Sprintf(" (%d earlier reports of this kind not audited)", num.unaudited)
		}
		st.alert(r.Context(), severity, summary, map[string]any{
			"event": "task_end", "atespace": actor.Atespace, "actor": actor.Name, "actor_uid": actor.UID,
			"batch_id": reg.BatchID, "exit_code": in.ExitCode, "stalled": in.Stalled, "cause": cause, "duration_ms": max(in.DurationMS, 0),
			"report": num.total, "kind_count": num.count, "unaudited": num.unaudited, "repeat": num.total > 1,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// serveSubstrateRelayTamper takes a relay guard trip (GAP-0120): POST
// {"connector", "reason"} when the relay stopped the agent because
// DefenseClaw's hook folder moved. The gateway writes a HIGH audit row, so
// the trip reaches the alert views and not only the relay's log. The agent
// shares the actor's token and could post one too; the row says the actor
// reported it, and the actor listener's rate limit bounds the rows. 204 when
// taken.
func (a *APIServer) serveSubstrateRelayTamper(st *substrateState, w http.ResponseWriter, r *http.Request) {
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
	var in struct {
		Connector string `json:"connector"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in); err != nil {
		writeSubstrateRefusal(w, http.StatusBadRequest, "bad_report")
		return
	}
	if st.alert != nil {
		reason, connector := substrateReportText(in.Reason), substrateReportText(in.Connector)
		st.alert(r.Context(), "HIGH", fmt.Sprintf("hook-folder integrity guard stopped the agent of %s/%s (reported by the actor): %s", actor.Atespace, actor.Name, reason),
			map[string]any{"event": "relay_guard_tamper", "atespace": actor.Atespace, "actor": actor.Name, "actor_uid": actor.UID,
				"connector": connector, "reason": reason})
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
