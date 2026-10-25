// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Protected-target corpus (GAP-0973): a call that reaches the gateway before
// its session's start waits for that start, and its block refuses the call.
// A start that never comes costs one short wait per session, and nothing
// without an arrival wait.
func TestSessionStartGateCallBeforeItsStart(t *testing.T) {
	var gate sessionStartGate
	ctx := t.Context()
	type result struct {
		reason string
		refuse bool
	}
	early := make(chan result, 1)
	go func() {
		reason, refuse := gate.await(ctx, "late", 5*time.Second, 3*time.Second)
		early <- result{reason, refuse}
	}()
	time.Sleep(100 * time.Millisecond)
	gate.begin("late").finish(true, "unapproved hook ~/.codex/hooks.json")
	if got := <-early; !got.refuse || !strings.Contains(got.reason, "unapproved hook") {
		t.Fatalf("a call before its blocked start ran: %+v", got)
	}

	began := time.Now()
	if reason, refuse := gate.await(ctx, "never", time.Second, 50*time.Millisecond); refuse {
		t.Fatalf("a session whose start never came was refused: %s", reason)
	}
	if time.Since(began) < 50*time.Millisecond {
		t.Fatal("the first call did not wait for its start to arrive")
	}
	began = time.Now()
	if _, refuse := gate.await(ctx, "never", time.Second, 5*time.Second); refuse || time.Since(began) > time.Second {
		t.Fatalf("a later call of the session waited again: refuse=%t after %s", refuse, time.Since(began))
	}
	began = time.Now()
	if _, refuse := gate.await(ctx, "unwaited", time.Second, 0); refuse || time.Since(began) > 500*time.Millisecond {
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
