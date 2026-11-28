// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
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
// a failure, HIGH for a run the relay ended) that names how it ended
// (finished, failed, or ended by the relay for making no progress, with the
// relay's reason) and marks the actor's activity with a task_end, on which
// the controller suspends the actor and frees its worker.
//
// The route takes the actor's verified JWT like every actor route, and the
// agent shares that token: it could post here itself, and the gateway
// cannot tell its reports from the relay's. So the row says the actor
// reported it, and no report is dropped (GAP-0291): every one is a row of
// its own, numbered per actor on this replica (those after the first are
// marked as repeats), so ends the agent posted first cannot hide the
// relay's own. The actor listener's per-actor rate limit bounds the rows,
// as it bounds hook rows. What the agent cannot do is mint alerts at that
// rate (GAP-0303): a MEDIUM or HIGH report keeps its severity only while
// it is one of the first substrateTaskEndLoudRows of its kind (severity,
// exit code, cause) and the actor has at most substrateTaskEndMaxKinds
// kinds of that severity; any other is written at INFO with the reported
// severity in the row. Each severity has its own kind budget and INFO
// reports use none, so finishes or failures the agent posts cannot turn
// the relay's HIGH end into an INFO row before the actor has HIGH rows in
// the alert path. So at most 2 x 16 x 3 = 96 rows per actor and replica
// are MEDIUM or HIGH (48 of each). Early ends cost the
// agent only its own worker (the controller suspends a task actor that
// stays quiet after its end). A relay-only credential is the root fix
// (tracked in GAP-0291).

const (
	// substrateTaskEndMaxActors bounds the per-actor report counts.
	substrateTaskEndMaxActors = 10000
	// substrateTaskEndMaxKinds bounds the kinds of end counted per actor
	// and severity (MEDIUM, HIGH).
	substrateTaskEndMaxKinds = 16
	// substrateTaskEndLoudRows is how many reports of a kind keep their severity.
	substrateTaskEndLoudRows = 3
	substrateTaskCauseMax    = 512
)

// substrateTaskEndCounts is one actor's report counts. Kinds are keyed by a
// digest, so an entry stays small whatever the agent puts in a cause; only
// MEDIUM and HIGH kinds are kept, at most substrateTaskEndMaxKinds each.
type substrateTaskEndCounts struct {
	total    int
	kinds    map[[16]byte]int
	distinct map[string]int // kinds per severity
}

// substrateTaskEnds counts the end reports per actor UID.
type substrateTaskEnds struct {
	mu   sync.Mutex
	rows map[string]*substrateTaskEndCounts
}

// substrateTaskEndNumber says how a report is counted: its number among the
// actor's reports, its number among the reports of its kind (0 for an INFO
// report, which is not counted by kind, and when the actor already has
// substrateTaskEndMaxKinds other kinds of its severity), and whether its
// row keeps the reported severity.
type substrateTaskEndNumber struct {
	total, count int
	keep         bool
}

// next numbers uid's report of the given severity and kind (the kind
// includes the severity).
func (t *substrateTaskEnds) next(uid, severity, kind string) substrateTaskEndNumber {
	key := sha256.Sum256([]byte(kind))
	k := [16]byte(key[:16])
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rows == nil || len(t.rows) >= substrateTaskEndMaxActors {
		t.rows = map[string]*substrateTaskEndCounts{}
	}
	c := t.rows[uid]
	if c == nil {
		c = &substrateTaskEndCounts{kinds: map[[16]byte]int{}, distinct: map[string]int{}}
		t.rows[uid] = c
	}
	c.total++
	out := substrateTaskEndNumber{total: c.total}
	if severity == "INFO" {
		// INFO is written at INFO anyway: it uses no kind slot.
		out.keep = true
		return out
	}
	if _, seen := c.kinds[k]; !seen {
		if c.distinct[severity] >= substrateTaskEndMaxKinds {
			return out
		}
		c.distinct[severity]++
	}
	c.kinds[k]++
	out.count = c.kinds[k]
	out.keep = out.count <= substrateTaskEndLoudRows
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
		num := st.taskEnds.next(actor.UID, severity, fmt.Sprintf("%s|%d|%s", severity, in.ExitCode, cause))
		took := (time.Duration(max(in.DurationMS, 0)) * time.Millisecond).Round(time.Second)
		summary := fmt.Sprintf("task %s: %s/%s exit %d after %s (reported by the actor)", outcome, actor.Atespace, actor.Name, in.ExitCode, took)
		if cause != "" {
			summary += "; " + cause
		}
		if num.total > 1 {
			summary = fmt.Sprintf("repeat %d: %s", num.total, summary)
		}
		row := severity
		if !num.keep && severity != "INFO" {
			row = "INFO"
			if num.count == 0 {
				summary += fmt.Sprintf(" [reported %s; written at INFO: the actor already reported %d other kinds of %s end]", severity, substrateTaskEndMaxKinds, severity)
			} else {
				summary += fmt.Sprintf(" [reported %s; written at INFO: report %d of this kind]", severity, num.count)
			}
		}
		st.alert(r.Context(), row, summary, map[string]any{
			"event": "task_end", "atespace": actor.Atespace, "actor": actor.Name, "actor_uid": actor.UID,
			"batch_id": reg.BatchID, "exit_code": in.ExitCode, "stalled": in.Stalled, "cause": cause, "duration_ms": max(in.DurationMS, 0),
			"report": num.total, "repeat": num.total > 1, "kind_count": num.count, "reported_severity": severity,
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
