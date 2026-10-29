// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// GAP-1459: a session that was running when the gateway restarted will not
// send its SessionStart again. Its first call after the restart must not
// wait the whole arrival window for it: the saved record shows an earlier
// process recorded its start, so the call judges that start in its place at
// once (the GAP-1448 check still runs and still blocks). A session with no
// record keeps the wait.
func TestSessionStartRecordedBeforeRestartDoesNotWait(t *testing.T) {
	saved := sessionStartArrivalWait
	sessionStartArrivalWait = 5 * time.Second
	t.Cleanup(func() { sessionStartArrivalWait = saved })
	h := newSessionStartGateHarness(t)
	cwd := t.TempDir()

	for _, session := range []string{"running-allowed", "running-blocked"} {
		startDone := make(chan int, 1)
		go func() {
			code, _ := h.post("SessionStart", session, map[string]interface{}{"source": "startup", "cwd": cwd})
			startDone <- code
		}()
		<-h.started
		h.repair <- nil
		if code := <-startDone; code != 200 {
			t.Fatalf("%s: SessionStart status %d", session, code)
		}
		if !h.api.sessionStartRecordedEarlier(withAuthenticatedHookConnector(context.Background(), "codex"), "codex", session) {
			t.Fatalf("%s: the start left no saved record", session)
		}
	}
	// The gateway restarts: this process has seen no start.
	h.api.sessionStartGate = sessionStartGate{}

	call := func(session string, repair error) (string, []string, time.Duration) {
		t.Helper()
		type answer struct {
			action   string
			findings []string
		}
		done := make(chan answer, 1)
		begin := time.Now()
		go func() {
			action, findings := h.toolCall(session)
			done <- answer{action, findings}
		}()
		select {
		case <-h.started:
			h.repair <- repair
		case got := <-done:
			t.Fatalf("%s: the call ran without judging the start in its place: %+v", session, got)
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: no answer", session)
		}
		got := <-done
		return got.action, got.findings, time.Since(begin)
	}
	action, findings, took := call("running-allowed", nil)
	if action == guardrailActionBlock {
		t.Fatalf("running session after a restart: %s %v", action, findings)
	}
	if took >= sessionStartArrivalWait {
		t.Fatalf("running session after a restart waited the arrival window: %s", took)
	}
	action, findings, took = call("running-blocked", errors.New("registration missing"))
	if action != guardrailActionBlock || !slices.Contains(findings, "SESSION-START-BLOCKED") {
		t.Fatalf("running session whose judged start blocks: %s %v", action, findings)
	}
	if took >= sessionStartArrivalWait {
		t.Fatalf("running blocked session after a restart waited the arrival window: %s", took)
	}
}

// GAP-1822: the arrival wait uses no gateway CPU, so the call gives its
// caller's run slot up for the window and takes it back after.
func TestSessionStartArrivalWaitGivesUpTheRunSlot(t *testing.T) {
	run := make(chan struct{}, 1)
	run <- struct{}{}
	slot := &hookRunSlot{run: run, held: true}
	ctx := context.WithValue(context.Background(), hookRunSlotContextKey{}, slot)
	var gate sessionStartGate
	free := make(chan bool, 1)
	go func() {
		select {
		case run <- struct{}{}:
			<-run
			free <- true
		case <-time.After(5 * time.Second):
			free <- false
		}
	}()
	if reason, refuse := gate.await(ctx, "codex\x00\x00unseen", 10*time.Second, time.Second, func(context.Context) (bool, string) { return false, "" }); refuse {
		t.Fatalf("allowed judged start refused: %s", reason)
	}
	if !<-free {
		t.Fatal("the run slot stayed held for the whole arrival window")
	}
	slot.mu.Lock()
	held := slot.held
	slot.mu.Unlock()
	if !held || len(run) != 1 {
		t.Fatalf("the run slot was not taken back: held=%t tokens=%d", held, len(run))
	}
}

// A request whose context ends while the arrival wait takes its run slot
// back (another call holds the slot) is refused as pending and its start
// is not judged with the done context (pod check6 note on GAP-1822).
func TestSessionStartArrivalWaitEndedWhileTakingTheSlotBackIsNotJudged(t *testing.T) {
	run := make(chan struct{}, 1)
	run <- struct{}{}
	slot := &hookRunSlot{run: run, held: true}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), hookRunSlotContextKey{}, slot))
	defer cancel()
	var gate sessionStartGate
	taken := make(chan struct{})
	go func() {
		// Another call takes the freed slot and keeps it past the window.
		run <- struct{}{}
		close(taken)
		time.Sleep(400 * time.Millisecond)
		cancel()
	}()
	judged := false
	reason, refuse := gate.await(ctx, "codex\x00\x00unseen-ended", 10*time.Second, 100*time.Millisecond, func(context.Context) (bool, string) {
		judged = true
		return true, "judged with a done context"
	})
	<-taken
	if !refuse || reason != sessionStartPendingReason {
		t.Fatalf("ended request: refuse=%t reason=%q, want the pending refusal", refuse, reason)
	}
	if judged {
		t.Fatal("the start was judged with a done context")
	}
	gate.mu.Lock()
	_, blocked := gate.entries["codex\x00\x00unseen-ended"]
	gate.mu.Unlock()
	if blocked {
		t.Fatal("an ended request left a start verdict for the session")
	}
}
