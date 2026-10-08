// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"testing"
	"time"
)

// A newly discovered root must not borrow another session's loaded policy
// while its PID is being added to Tetragon: its user accrues nothing until
// the policy holds it, and keeps the covered time measured before. Every
// new session restarted the window, so no user who starts agents during a
// burn-in ever finished it (GAP-0088).
func TestNewSessionWaitsForLoadedPolicyBeforeBurnIn(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = []Proc{nativeProc(4001, 1, 100, 1001, aliceClaudeNew)}
	h.pass()
	h.burnedIn(1001, 24*time.Hour)
	h.procs = append(h.procs, codexProc(4002, 1, 200, 1001))
	if !h.ctl.rescan() {
		t.Fatal("new session did not trigger a policy pass")
	}
	if got := h.covered(1001); got != 24*time.Hour {
		t.Fatalf("a new session restarted the window: covered %v, want the 24h measured before", got)
	}
	if s := userState(h, 1001); s.Reason != "kernel_session_policy_pending" || s.CoveredSeconds != int64(24*time.Hour/time.Second) {
		t.Fatalf("pending session status = %+v", s)
	}
	if !h.has("kernel_session_policy_pending:1") {
		t.Fatalf("pending warning missing: %v", h.status().Warnings)
	}
	h.accrueTick()
	if got := h.covered(1001); got != 24*time.Hour {
		t.Fatalf("unloaded session accrued: covered %v", got)
	}
	h.pass()
	if h.has("kernel_session_policy_pending") {
		t.Fatalf("pending after policy load: %v", h.status().Warnings)
	}
	h.accrueTick()
	if got := h.covered(1001); got != 24*time.Hour+time.Minute {
		t.Fatalf("loaded session covered %v, want one minute more", got)
	}
}

// The tick credited after the scans that did not yet see a new session is
// taken back (the session may have run in it unmeasured); older ticks stay.
func TestNewSessionTakesBackOnlyTheTickItMayHaveRunUnmeasured(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = []Proc{nativeProc(4001, 1, 100, 1001, aliceClaudeNew)}
	h.pass()
	h.accrueTick() // the stream comes up: one covered minute
	for range 12 {
		h.now = h.now.Add(5 * time.Second)
		h.ctl.rescan()
	}
	h.now = h.now.Add(2 * time.Second)
	h.ctl.accrue()
	if got := h.covered(1001); got != 2*time.Minute {
		t.Fatalf("covered %v before the new session, want 2m", got)
	}
	h.procs = append(h.procs, codexProc(4002, 1, 200, 1001))
	h.now = h.now.Add(3 * time.Second)
	h.ctl.rescan()
	if got := h.covered(1001); got != time.Minute {
		t.Fatalf("covered %v after the new session, want 1m: only the tick after the scans before it goes", got)
	}
}

func TestFailedPolicyReplacementKeepsNewSessionUnmeasured(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = []Proc{nativeProc(4001, 1, 100, 1001, aliceClaudeNew)}
	h.pass()
	h.procs = append(h.procs, codexProc(4002, 1, 200, 1001))
	h.tg.failAll = true
	h.pass()
	if s := userState(h, 1001); s.Reason != "kernel_session_policy_pending" {
		t.Fatalf("failed replacement status = %+v", s)
	}
	h.accrueTick()
	if got := h.covered(1001); got != 0 {
		t.Fatalf("failed replacement accrued %v", got)
	}
	h.tg.failAll = false
	h.pass()
	if h.has("kernel_session_policy_pending") {
		t.Fatalf("pending after repair: %v", h.status().Warnings)
	}
}

func TestShellStartedSessionMeasuresAfterPolicyLoad(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	shell := Proc{PID: 3900, PPID: 1, StartTicks: 100, UID: 1001, EUID: 1001,
		Exe: "/usr/bin/bash", Host: true}
	h.procs = []Proc{shell, nativeProc(4001, shell.PID, 200, 1001, aliceClaudeNew)}
	h.pass()
	if h.has("kernel_session_policy_pending") {
		t.Fatalf("loaded shell-started session is pending: %v pids=%v recorded=%v roots=%+v", h.status().Warnings, h.ctl.lastPIDs, h.ctl.recorded, h.ctl.roots.Roots)
	}
	h.accrueTick()
	if got := h.covered(1001); got != time.Minute {
		t.Fatalf("shell-started session covered %v, want one minute", got)
	}
}

// A restarted helper accrues nothing while it is down or while a session
// waits for the controls policy, and keeps the evidence measured before.
func TestRestoredCleanTimeSurvivesTheFirstSessionsWait(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.burnedIn(1001, 24*time.Hour)
	h.start(observeIntent()) // persisted burn-in evidence, no policy record
	h.procs = []Proc{codexProc(4002, 1, 200, 1001)}
	h.pass()
	if got := h.covered(1001); got != 24*time.Hour {
		t.Fatalf("a restart and an uncovered first session voided the restored clean time: covered %v", got)
	}
}

func TestDisplacedRootStaysPendingBeyondPIDBudget(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	for i := 0; i < MaxPIDs; i++ {
		h.procs = append(h.procs, codexProc(7000+i, 1, uint64(100+i), 1001))
	}
	h.pass()
	h.burnedIn(1001, 24*time.Hour)
	// A previously missed older root enters the scan and takes a place in
	// the bounded policy. The displaced live root must now stop clean time.
	h.procs = append(h.procs, codexProc(8000, 1, 50, 1001))
	h.pass()
	if s := userState(h, 1001); s.Reason != WarnSessionPolicyPending {
		t.Fatalf("uncovered existing root did not pause burn-in: %+v", s)
	}
	h.accrueTick()
	if got := h.covered(1001); got != 24*time.Hour {
		t.Fatalf("user covered %v with an uncovered root, want the 24h measured before (no accrual, no restart)", got)
	}
}
