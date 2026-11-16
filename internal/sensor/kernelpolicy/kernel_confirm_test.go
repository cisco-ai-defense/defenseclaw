// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package kernelpolicy

import (
	"fmt"
	"testing"
)

func observedWith(h *harness, reason string) []Observed {
	var out []Observed
	for _, o := range h.status().Roots.Observed {
		if o.Reason == reason {
			out = append(out, o)
		}
	}
	return out
}

// GAP-0166: status called the AD user's Claude session anchored and the user
// enforcing because the session fit the loaded controls by every check the
// helper makes on /proc, while the kernel never marked it. A native session
// now counts as anchored only once Tetragon itself reported its start on the
// event stream (its exec hook is what marks the session). Until then the
// user is armed with the reason, the session is observed-only, and a
// warning counts it.
func TestASessionTetragonDidNotReportIsNotAnchored(t *testing.T) {
	h := enforcing(t)
	h.noStarts = true
	before := h.status().Roots.Anchored // bob's session in the monitor-only family
	h.procs = append(h.procs, nativeProc(4010, 1, 300, 1001, aliceClaudeNew))
	h.pass()
	alice := userState(h, 1001)
	if alice.State != UIDArmed || alice.Reason != ReasonKernelUnconfirmed || alice.AnchoredRoots != 0 {
		t.Fatalf("alice with an unreported session = %+v, want armed (%s) with 0 anchored", alice, ReasonKernelUnconfirmed)
	}
	if got := h.status().Roots.Anchored; got != before {
		t.Fatalf("roots.anchored = %d, want %d: the unreported session is not anchored", got, before)
	}
	if !h.has(WarnSessionsUnconfirmed) {
		t.Fatalf("warnings %v lack %s", h.status().Warnings, WarnSessionsUnconfirmed)
	}
	if got := observedWith(h, ReasonKernelUnconfirmed); len(got) != 1 ||
		got[0] != (Observed{UID: 1001, Reason: ReasonKernelUnconfirmed, Connector: "claudecode", Count: 1}) {
		t.Fatalf("observed = %+v", got)
	}

	// Tetragon reports a start under another binary: still not this session.
	h.ctl.RecordExec(Exec{PID: 4010, Exe: "/usr/bin/bash", At: h.now})
	h.pass()
	if alice := userState(h, 1001); alice.State != UIDArmed {
		t.Fatalf("a start of another binary confirmed the session: %+v", alice)
	}

	// Its own start: anchored, enforcing, no warning.
	h.ctl.RecordExec(Exec{PID: 4010, ExecID: "x", Exe: aliceClaudeNew, At: h.now})
	h.pass()
	alice = userState(h, 1001)
	if alice.State != UIDEnforcing || alice.AnchoredRoots != 1 || alice.Reason != "" {
		t.Fatalf("alice after Tetragon reported the start = %+v, want enforcing with 1 anchored", alice)
	}
	if h.has(WarnSessionsUnconfirmed) || len(observedWith(h, ReasonKernelUnconfirmed)) != 0 {
		t.Fatalf("still reported unconfirmed: %v %+v", h.status().Warnings, h.status().Roots.Observed)
	}

	// A helper restart keeps the confirmed session (by pid and start time).
	h.start(h.intent)
	h.pass()
	if alice := userState(h, 1001); alice.State != UIDEnforcing || alice.AnchoredRoots != 1 {
		t.Fatalf("alice after a helper restart = %+v, want the confirmed session kept", alice)
	}

	// The session ends and its pid is reused by a new session of the same
	// binary that Tetragon did not report: a reused pid is not confirmed.
	h.procs = []Proc{codexProc(5001, 1, 120, 1002), nativeProc(4010, 1, 900, 1001, aliceClaudeNew)}
	h.pass()
	if alice := userState(h, 1001); alice.State != UIDArmed || alice.Reason != ReasonKernelUnconfirmed {
		t.Fatalf("a reused pid = %+v, want armed (%s)", alice, ReasonKernelUnconfirmed)
	}
}

// An exit the stream missed must not let a reused pid inherit a start:
// a loss forgets the starts no root has claimed yet.
func TestALossForgetsUnclaimedStarts(t *testing.T) {
	h := enforcing(t)
	h.noStarts = true
	h.ctl.RecordExec(Exec{PID: 4010, Exe: aliceClaudeNew, At: h.now})
	h.ctl.RecordLoss()
	h.procs = append(h.procs, nativeProc(4010, 1, 300, 1001, aliceClaudeNew))
	h.pass()
	if alice := userState(h, 1001); alice.State != UIDArmed || alice.Reason != ReasonKernelUnconfirmed {
		t.Fatalf("alice = %+v, want armed: the start was recorded before a loss", alice)
	}
	h.ctl.RecordExec(Exec{PID: 4010, ExecID: "a", Exe: aliceClaudeNew, At: h.now})
	h.ctl.RecordExit(4010, "a")
	h.pass()
	if alice := userState(h, 1001); alice.State != UIDArmed {
		t.Fatalf("alice = %+v, want armed: that start exited", alice)
	}
}

// Only starts of a binary in a loaded controls policy are kept, and the
// memory for them is bounded.
func TestStartsOfOtherBinariesAreNotKept(t *testing.T) {
	h := enforcing(t)
	for i := 0; i < maxExecs+10; i++ {
		h.ctl.RecordExec(Exec{PID: 100000 + i, Exe: fmt.Sprintf("/usr/bin/tool%d", i), At: h.now})
	}
	h.ctl.execMu.Lock()
	n := len(h.ctl.execs)
	h.ctl.execMu.Unlock()
	if n != 0 {
		t.Fatalf("%d starts of unrelated binaries kept", n)
	}
	for i := 0; i < maxExecs+10; i++ {
		h.ctl.RecordExec(Exec{PID: 100000 + i, Exe: aliceClaudeNew, At: h.now})
	}
	h.ctl.execMu.Lock()
	n = len(h.ctl.execs)
	h.ctl.execMu.Unlock()
	if n > maxExecs {
		t.Fatalf("%d starts kept, bound %d", n, maxExecs)
	}
}

// A user with no session that fits the controls is armed for that reason.
func TestArmedReasonNamesAMissingSession(t *testing.T) {
	h := enforcing(t) // alice's only session predates the load
	if alice := userState(h, 1001); alice.State != UIDArmed || alice.Reason != ReasonNoAnchoredSession {
		t.Fatalf("alice = %+v, want armed (%s)", alice, ReasonNoAnchoredSession)
	}
}
