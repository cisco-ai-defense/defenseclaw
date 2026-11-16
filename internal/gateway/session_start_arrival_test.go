// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Protected-target corpus (GAP-0973, GAP-1448): a call that reaches the
// gateway before its session's start waits for that start, and its block
// refuses the call. A start that does not arrive in time is judged in its
// place, never taken as allowed: its check's block refuses the call and the
// session's later calls, a check that does not finish blocks, and a later
// start replaces the judged verdict. A judged allow costs one short wait per
// session, and nothing without an arrival wait.
func TestSessionStartGateCallBeforeItsStart(t *testing.T) {
	var gate sessionStartGate
	ctx := t.Context()
	type result struct {
		reason string
		refuse bool
	}
	unexpected := func(context.Context) (bool, string) {
		t.Error("judged a start that arrived")
		return false, ""
	}
	early := make(chan result, 1)
	go func() {
		reason, refuse := gate.await(ctx, "late", 5*time.Second, 3*time.Second, unexpected)
		early <- result{reason, refuse}
	}()
	time.Sleep(100 * time.Millisecond)
	gate.begin("late").finish(true, "unapproved hook ~/.codex/hooks.json")
	if got := <-early; !got.refuse || !strings.Contains(got.reason, "unapproved hook") {
		t.Fatalf("a call before its blocked start ran: %+v", got)
	}

	// GAP-1448: the blocking start comes after the arrival wait.
	checks := 0
	registrationMissing := func(context.Context) (bool, string) {
		checks++
		return true, "Codex runtime registration is unavailable"
	}
	for call := range 2 {
		reason, refuse := gate.await(ctx, "slow-blocked", time.Second, 20*time.Millisecond, registrationMissing)
		if !refuse || !strings.Contains(reason, "registration is unavailable") {
			t.Fatalf("call %d of a session whose blocking start came late ran: refuse=%t reason=%q", call, refuse, reason)
		}
	}
	if checks != 1 {
		t.Fatalf("the missing start was judged %d times, want once", checks)
	}
	gate.begin("slow-blocked").finish(false, "")
	if reason, refuse := gate.await(ctx, "slow-blocked", time.Second, 20*time.Millisecond, unexpected); refuse {
		t.Fatalf("the late allowed start did not replace the judged block: %s", reason)
	}

	for name, check := range map[string]func(context.Context) (bool, string){
		"missing check":   nil,
		"panicking check": func(context.Context) (bool, string) { panic("check failed") },
	} {
		if reason, refuse := gate.await(ctx, name, time.Second, 20*time.Millisecond, check); !refuse ||
			!strings.Contains(reason, sessionStartUnfinishedReason) {
			t.Fatalf("%s: a start judged without a verdict ran: refuse=%t reason=%q", name, refuse, reason)
		}
	}

	allowed := func(context.Context) (bool, string) {
		checks++
		return false, ""
	}
	checks = 0
	began := time.Now()
	if reason, refuse := gate.await(ctx, "never", time.Second, 50*time.Millisecond, allowed); refuse {
		t.Fatalf("a session whose judged start was allowed was refused: %s", reason)
	}
	if time.Since(began) < 50*time.Millisecond {
		t.Fatal("the first call did not wait for its start to arrive")
	}
	began = time.Now()
	if _, refuse := gate.await(ctx, "never", time.Second, 5*time.Second, allowed); refuse || time.Since(began) > time.Second || checks != 1 {
		t.Fatalf("a later call of the session waited or judged again: refuse=%t after %s, checks=%d", refuse, time.Since(began), checks)
	}
	began = time.Now()
	if _, refuse := gate.await(ctx, "unwaited", time.Second, 0, unexpected); refuse || time.Since(began) > 500*time.Millisecond {
		t.Fatal("a call without an arrival wait waited")
	}
}

// The arrival wait applies only where a start verdict can block: action
// mode, for a connector that sends a session start.
func TestSessionStartArrivalOnlyWhereAStartCanBlock(t *testing.T) {
	saved := sessionStartArrivalWait
	sessionStartArrivalWait = time.Second
	t.Cleanup(func() { sessionStartArrivalWait = saved })
	starts := connector.HookProfile{SupportedEvents: []string{"SessionStart", "PreToolUse"}}
	noStart := connector.HookProfile{SupportedEvents: []string{"PreToolUse"}}
	action := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
	observe := instructionProtectionTestAPI(t, "codex", "observe", "HIGH")
	if got := action.sessionStartArrival(t.Context(), starts, "codex"); got != time.Second {
		t.Fatalf("action mode arrival = %s", got)
	}
	if got := observe.sessionStartArrival(t.Context(), starts, "codex"); got != 0 {
		t.Fatalf("observe mode arrival = %s", got)
	}
	if got := action.sessionStartArrival(t.Context(), noStart, "codex"); got != 0 {
		t.Fatalf("arrival for a connector without a start = %s", got)
	}
}
