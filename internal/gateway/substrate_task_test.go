// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The substrate fixture (substrate_listener_test.go) is not built on Windows.

//go:build !windows

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-0273, GAP-0274: a --task actor's relay reports how the task ended;
// the gateway audits it and marks a task_end for the controller.
func TestSubstrateRelayTaskEnd(t *testing.T) {
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	ctx := context.Background()
	reg, _, _ := f.regs.Get(ctx, "eng-web", subUID2)
	reg.TaskDigest = "3f0a9c2e8b7d6f5a4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a2918f7e6d5c"
	if err := f.regs.Put(ctx, reg); err != nil {
		t.Fatal(err)
	}
	body := `{"exit_code":124,"stalled":true,"duration_ms":901000,"cause":"the task made no progress for 10m0s\u0007; the cluster gateway answers"}`
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-bob", body); rec.Code != http.StatusNoContent {
		t.Fatalf("task end: %d %s", rec.Code, rec.Body)
	}
	f.mu.Lock()
	marks := strings.Join(f.activity, ",")
	f.mu.Unlock()
	if !strings.Contains(marks, SubstrateActivityTaskEnd+":"+subUID2) {
		t.Fatalf("activity %s: no task_end mark", marks)
	}
	events, err := store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	var row *audit.Event
	for i := range events {
		if strings.Contains(events[i].Details, "task_end") {
			row = &events[i]
		}
	}
	if row == nil || !strings.Contains(row.Details, `"source":"substrate"`) || row.Severity != "HIGH" ||
		!strings.Contains(row.Details, "task ended by the relay: eng-web/bob-1 exit 124 after 15m1s") ||
		!strings.Contains(row.Details, "no progress for 10m0s ; the cluster gateway answers") ||
		!strings.Contains(row.Details, `"batch_id":"b1"`) {
		t.Fatalf("audit row %+v (of %d)", row, len(events))
	}
	// An interactive actor has no task to end.
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-alice", `{"exit_code":0}`); rec.Code != http.StatusForbidden {
		t.Fatalf("interactive actor: %d", rec.Code)
	}
	if rec := f.do(t, f.actor, http.MethodGet, substrateRelayTask, "tok-bob", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", rec.Code)
	}
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "", `{"exit_code":0}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no actor token: %d", rec.Code)
	}
	// GAP-0291: no report is dropped; those after the first are repeats.
	for range 4 {
		f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-bob", `{"exit_code":0}`)
	}
	events, _ = store.ListEvents(100)
	n, repeats := 0, 0
	for _, e := range events {
		if strings.Contains(e.Details, "task_end") && strings.Contains(e.Details, "eng-web/bob-1") {
			n++
			if strings.Contains(e.Details, `"repeat":true`) && strings.Contains(e.Details, "repeat ") {
				repeats++
			}
		}
	}
	if n != 5 || repeats != 4 {
		t.Fatalf("%d task-end rows (%d repeats) for 5 reports, want 5 (4 repeats)", n, repeats)
	}
}

// taskEndFixture is the substrate fixture with bob-1 as a --task actor and
// an audit store; rows returns bob-1's task-end rows that contain marker.
func taskEndFixture(t *testing.T) (*substrateFixture, func(marker string) []audit.Event) {
	t.Helper()
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	ctx := context.Background()
	reg, _, _ := f.regs.Get(ctx, "eng-web", subUID2)
	reg.TaskDigest = "3f0a9c2e8b7d6f5a4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a2918f7e6d5c"
	if err := f.regs.Put(ctx, reg); err != nil {
		t.Fatal(err)
	}
	rows := func(marker string) []audit.Event {
		t.Helper()
		events, err := store.ListEvents(5000)
		if err != nil {
			t.Fatal(err)
		}
		var out []audit.Event
		for _, e := range events {
			if strings.Contains(e.Details, `"event":"task_end"`) && strings.Contains(e.Details, "eng-web/bob-1") && strings.Contains(e.Details, marker) {
				out = append(out, e)
			}
		}
		return out
	}
	return f, rows
}

// postTaskEnd posts one task-end report as bob-1.
func postTaskEnd(t *testing.T, f *substrateFixture, body string) {
	t.Helper()
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-bob", body); rec.Code != http.StatusNoContent {
		t.Fatalf("task end %s: %d %s", body, rec.Code, rec.Body)
	}
}

// bySeverity counts rows per severity.
func bySeverity(rows []audit.Event) map[string]int {
	out := map[string]int{}
	for _, e := range rows {
		out[e.Severity]++
	}
	return out
}

// GAP-0303 (expected item 3): a flood of one kind of end keeps every row and
// the exact count, but only the first few keep their severity, so the agent
// cannot mint HIGH rows at the actor rate limit. A different kind of end
// after the flood keeps its own.
func TestGAP0303TaskEndRepeatsAreWrittenAtInfo(t *testing.T) {
	f, rows := taskEndFixture(t)
	const flood = 100
	for range flood {
		postTaskEnd(t, f, `{"exit_code":124,"stalled":true,"duration_ms":1000,"cause":"FLOODMARK agent chosen"}`)
	}
	postTaskEnd(t, f, `{"exit_code":124,"stalled":true,"duration_ms":901000,"cause":"OWNMARK the task made no progress for 10m0s"}`)
	f.mu.Lock()
	marks := 0
	for _, m := range f.activity {
		if m == SubstrateActivityTaskEnd+":"+subUID2 {
			marks++
		}
	}
	f.mu.Unlock()
	if marks != flood+1 {
		t.Fatalf("%d task_end marks for %d reports: every report marks the activity", marks, flood+1)
	}
	got := rows("FLOODMARK")
	sev := bySeverity(got)
	if len(got) != flood || sev["HIGH"] != 3 || sev["INFO"] != flood-3 {
		t.Fatalf("%d rows for %d reports (%v), want every report a row, 3 HIGH and the rest INFO", len(got), flood, sev)
	}
	for _, e := range got {
		if !strings.Contains(e.Details, `"reported_severity":"HIGH"`) {
			t.Fatalf("row without the reported severity: %s", e.Details)
		}
	}
	if len(rows(`"kind_count":100,`)) != 1 || len(rows("written at INFO: report 100 of this kind")) != 1 {
		t.Fatal("report 100 of the flood does not carry its exact count")
	}
	own := rows("OWNMARK")
	if len(own) != 1 || own[0].Severity != "HIGH" {
		t.Fatalf("the relay's own end after the flood: %+v", own)
	}
}

// GAP-0303: distinct causes cannot defeat the bound. Past the actor's
// first kinds, every report is still a row, written at INFO.
func TestGAP0303TaskEndKindsAreBounded(t *testing.T) {
	f, rows := taskEndFixture(t)
	const reports = 200
	for i := range reports {
		postTaskEnd(t, f, fmt.Sprintf(`{"exit_code":124,"stalled":true,"cause":"KINDMARK %d"}`, i))
	}
	got := rows("KINDMARK")
	sev := bySeverity(got)
	if len(got) != reports || sev["HIGH"] != 16 || sev["INFO"] != reports-16 {
		t.Fatalf("%d rows for %d distinct-cause reports (%v), want 16 HIGH and the rest INFO", len(got), reports, sev)
	}
	last := rows(`"report":200,`)
	if len(last) != 1 || last[0].Severity != "INFO" || !strings.Contains(last[0].Details, `"kind_count":0,`) ||
		!strings.Contains(last[0].Details, "other kinds of end") {
		t.Fatalf("report 200: %+v", last)
	}
}

// GAP-0303 review (TST-3008, probes A to D): the agent cannot hide the
// relay's own end, whatever it posts first. Each case ends with the relay's
// report, which must be a row of its own with its reported severity.
func TestGAP0303AgentCannotMaskRelayEnd(t *testing.T) {
	stall := `"cause":"the task made no progress for 10m0s (no output, CPU or I/O); the cluster gateway answers, so the agent is stuck on a connection of its own. The task is ended with exit code 124."`
	cases := []struct {
		name, marker, reported string
		agent                  func(t *testing.T, f *substrateFixture)
		relay                  string
		want                   int // rows that contain marker after the relay's end
	}{
		{
			// A: 16 junk kinds and 3 more, then the relay's interrupted end.
			name: "A-kinds-full", marker: "RELAYMARK", reported: "MEDIUM",
			agent: func(t *testing.T, f *substrateFixture) {
				for i := range 16 {
					postTaskEnd(t, f, fmt.Sprintf(`{"exit_code":1,"cause":"junk %d"}`, i))
				}
				for i := range 3 {
					postTaskEnd(t, f, fmt.Sprintf(`{"exit_code":1,"cause":"overflow %d"}`, i))
				}
			},
			relay: `{"exit_code":75,"cause":"RELAYMARK the cluster gateway did not answer 2 hook calls during the task (the first: PreToolUse at 2026-11-19T07:00:01Z)"}`,
			want:  1,
		},
		{
			// B: 3 copies of the predictable stall text, then the real stall.
			name: "B-predictable-cause", marker: "no progress for 10m0s", reported: "HIGH",
			agent: func(t *testing.T, f *substrateFixture) {
				for range 3 {
					postTaskEnd(t, f, `{"exit_code":124,"stalled":true,"duration_ms":1,`+stall+`}`)
				}
			},
			relay: `{"exit_code":124,"stalled":true,"duration_ms":600000,` + stall + `}`,
			want:  4,
		},
		{
			// C: reports 4 to 7 of one kind each get a row.
			name: "C-tail", marker: "TAILMARK", reported: "MEDIUM",
			agent: func(t *testing.T, f *substrateFixture) {
				for range 6 {
					postTaskEnd(t, f, `{"exit_code":2,"cause":"TAILMARK"}`)
				}
			},
			relay: `{"exit_code":2,"cause":"TAILMARK"}`,
			want:  7,
		},
		{
			// D: about 52 s of agent reports at 20/s, then the relay's stall.
			name: "D-long-flood", marker: "DEEPMARK", reported: "HIGH",
			agent: func(t *testing.T, f *substrateFixture) {
				for i := range 16 {
					postTaskEnd(t, f, fmt.Sprintf(`{"exit_code":124,"stalled":true,"cause":"junk %d"}`, i))
				}
				for i := range 1025 {
					postTaskEnd(t, f, fmt.Sprintf(`{"exit_code":124,"stalled":true,"cause":"ovf %d"}`, i))
				}
			},
			relay: `{"exit_code":124,"stalled":true,"cause":"DEEPMARK relay stall"}`,
			want:  1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, rows := taskEndFixture(t)
			tc.agent(t, f)
			seen := map[string]bool{}
			for _, e := range rows("") {
				seen[e.ID] = true
			}
			postTaskEnd(t, f, tc.relay)
			all := rows("")
			var fresh []audit.Event
			for _, e := range all {
				if !seen[e.ID] {
					fresh = append(fresh, e)
				}
			}
			if len(fresh) != 1 || !strings.Contains(fresh[0].Details, tc.marker) {
				t.Fatalf("MASKED: the relay's end added %d rows (%d before)", len(fresh), len(seen))
			}
			if got := rows(tc.marker); len(got) != tc.want {
				t.Fatalf("%d rows with %q, want %d", len(got), tc.marker, tc.want)
			}
			if relay := fresh[0]; relay.Severity != tc.reported && !strings.Contains(relay.Details, `"reported_severity":"`+tc.reported+`"`) {
				t.Fatalf("the relay's row lost its severity %s: %s %s", tc.reported, relay.Severity, relay.Details)
			}
			// Bound: at most 16 kinds x 3 rows per actor are MEDIUM or HIGH.
			sev := bySeverity(all)
			if loud := sev["HIGH"] + sev["MEDIUM"]; loud > 16*3 {
				t.Fatalf("%d MEDIUM or HIGH rows for one actor (%v)", loud, sev)
			}
		})
	}
}
