// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// Protected-target corpus (GAP-1448): a Codex tool call whose blocking
// SessionStart reaches the gateway after the arrival wait is refused by the
// start's own check (the registration repair), judged in the start's place,
// not allowed because the wait ran out. Benign control: a session whose
// judged start is allowed runs, and judges it once.
func TestCodexCallJudgesTheStartThatDidNotArrive(t *testing.T) {
	saved := sessionStartArrivalWait
	sessionStartArrivalWait = 30 * time.Millisecond
	t.Cleanup(func() { sessionStartArrivalWait = saved })
	h := newSessionStartGateHarness(t)

	type call struct {
		action   string
		findings []string
	}
	toolCall := func(session string, repair error, wantRepair bool) call {
		t.Helper()
		done := make(chan call, 1)
		go func() {
			action, findings := h.toolCall(session)
			done <- call{action, findings}
		}()
		if wantRepair {
			select {
			case <-h.started:
				h.repair <- repair
			case got := <-done:
				t.Fatalf("session %s: the call ran without judging its missing start: %+v", session, got)
			case <-time.After(10 * time.Second):
				t.Fatalf("session %s: no answer", session)
			}
		}
		select {
		case got := <-done:
			return got
		case <-h.started:
			t.Fatalf("session %s: the start was judged again", session)
		case <-time.After(10 * time.Second):
			t.Fatalf("session %s: no answer", session)
		}
		return call{}
	}

	for i := range 2 {
		got := toolCall("late-blocked", errors.New("registration missing"), i == 0)
		if got.action != guardrailActionBlock || !slices.Contains(got.findings, "SESSION-START-BLOCKED") {
			t.Fatalf("call %d before a late blocking start: %+v", i, got)
		}
	}
	for i := range 2 {
		if got := toolCall("late-allowed", nil, i == 0); got.action == guardrailActionBlock {
			t.Fatalf("call %d of a session whose judged start was allowed: %+v", i, got)
		}
	}
	// The real start replaces the judged block.
	startDone := make(chan int, 1)
	go func() { code, _ := h.post("SessionStart", "late-blocked", nil); startDone <- code }()
	<-h.started
	h.repair <- nil
	if code := <-startDone; code != 200 {
		t.Fatalf("late SessionStart status %d", code)
	}
	if got := toolCall("late-blocked", nil, false); got.action == guardrailActionBlock {
		t.Fatalf("a call after the allowed late start: %+v", got)
	}
}
