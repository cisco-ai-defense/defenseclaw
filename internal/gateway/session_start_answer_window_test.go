// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// answerBoundedCallContext is the context of a call whose hook bounds its wait for
// the answer to window from now (hookJudgeAnswerEnd).
func answerBoundedCallContext(window time.Duration) context.Context {
	return context.WithValue(context.Background(), shellToolGateKey{}, time.Now().Add(window))
}

func withSessionStartAnswerReserve(t *testing.T, reserve time.Duration) {
	t.Helper()
	saved := sessionStartAnswerReserve
	sessionStartAnswerReserve = reserve
	t.Cleanup(func() { sessionStartAnswerReserve = saved })
}

// rel-1-0-3 GAP-0327: the first Codex call after a gateway start judged its
// session's missing start in its place (the registration repair) and waited
// for it past its hook's 3.5 s, and the hook denied the benign call. The call
// now goes on with its own verdict at the end of its answer window; the check
// runs on with a live context and its blocking verdict holds the later calls.
func TestMissingStartSlowerThanTheAnswerWindowLetsTheCallGoOn(t *testing.T) {
	withSessionStartAnswerReserve(t, 100*time.Millisecond)
	var g sessionStartGate
	release := make(chan struct{})
	var checks atomic.Int64
	var cutOff atomic.Bool
	check := func(ctx context.Context) (bool, string) {
		checks.Add(1)
		<-release
		cutOff.Store(ctx.Err() != nil)
		return true, "Codex runtime registration is unavailable"
	}
	start := time.Now()
	reason, refused := g.await(answerBoundedCallContext(400*time.Millisecond), "k", 10*time.Second, 20*time.Millisecond, check)
	if took := time.Since(start); refused || took > time.Second {
		t.Fatalf("call waited %v and refused=%v (%q); want it to go on inside its 400ms window", took, refused, reason)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		reason, refused = g.await(answerBoundedCallContext(400*time.Millisecond), "k", 10*time.Second, 20*time.Millisecond, check)
		if refused || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !refused || reason != sessionStartBlockedReason("Codex runtime registration is unavailable") {
		t.Fatalf("later call: refused=%v %q; want the blocking verdict of the judged start", refused, reason)
	}
	if checks.Load() != 1 || cutOff.Load() {
		t.Fatalf("start checks = %d (want 1), check context ended with its call = %v", checks.Load(), cutOff.Load())
	}
}

// A missing start whose check answers inside the call's window still decides
// the call (GAP-1448 unchanged): a blocking verdict refuses it.
func TestMissingStartCheckInsideTheWindowStillRefuses(t *testing.T) {
	withSessionStartAnswerReserve(t, 100*time.Millisecond)
	var g sessionStartGate
	check := func(context.Context) (bool, string) { return true, "registration missing" }
	reason, refused := g.await(answerBoundedCallContext(2*time.Second), "k", 10*time.Second, 20*time.Millisecond, check)
	if !refused || reason != sessionStartBlockedReason("registration missing") {
		t.Fatalf("refused=%v %q; want the start block", refused, reason)
	}
}

// A call of a session whose real start is still being judged is refused as
// pending (GAP-0806), now inside its answer window instead of after half its
// hook's transport timeout.
func TestPendingStartRefusalComesInsideTheAnswerWindow(t *testing.T) {
	withSessionStartAnswerReserve(t, 100*time.Millisecond)
	var g sessionStartGate
	ticket := g.begin("k")
	defer ticket.finish(false, "")
	start := time.Now()
	reason, refused := g.await(answerBoundedCallContext(500*time.Millisecond), "k", 10*time.Second, 0, nil)
	if took := time.Since(start); !refused || reason != sessionStartPendingReason || took > time.Second {
		t.Fatalf("refused=%v %q after %v; want the pending refusal inside the 500ms window", refused, reason, took)
	}
}

// A call without a bounded answer (no progress report, no shell tool gate)
// keeps the gate's own wait.
func TestUnboundedCallKeepsTheStartWait(t *testing.T) {
	var g sessionStartGate
	ticket := g.begin("k")
	go func() {
		time.Sleep(150 * time.Millisecond)
		ticket.finish(true, "slow start block")
	}()
	reason, refused := g.await(context.Background(), "k", 5*time.Second, 0, nil)
	if !refused || reason != sessionStartBlockedReason("slow start block") {
		t.Fatalf("refused=%v %q; want the start verdict that came after 150ms", refused, reason)
	}
}
