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

func TestEnforcingPolicyCannotDenyReusedPID(t *testing.T) {
	w := newWorld(t, baseTargets)
	roots := w.roots(codexProc(5001, 1, 120, 1002))
	compiled := w.compile(Input{Controls: &Scope{Mode: PolicyEnforce, UIDs: []int{1002}}, Roots: roots.Roots})
	if hasFamily(compiled, FamilyControls) {
		t.Fatal("a script-only live root cannot be safely enforced by its numeric pid")
	}
	if compiled.Anchored[1002] != 1 {
		t.Fatalf("the script root must stay measured in monitor mode: %v", compiled.Anchored)
	}
	if burnin := policyOf(t, compiled, FamilyBurnin); burnin.Mode != PolicyMonitor || len(burnin.PIDs) != 1 {
		t.Fatalf("unsafe script root did not stay in monitor mode: %+v", burnin)
	}

	monitor := w.compile(Input{Controls: &Scope{Mode: PolicyMonitor, UIDs: []int{1002}}, Roots: roots.Roots})
	policy := policyOf(t, monitor, FamilyControls)
	if len(policy.PIDs) != 1 || policy.PIDs[0] != 5001 {
		t.Fatalf("monitor lost its live-root measurement: %v", policy.PIDs)
	}
}

func TestScriptOnlyUserStaysMonitorAfterBurnIn(t *testing.T) {
	h := newHarness(t, enforceIntent(Digest(), "codex"), baseTargets)
	h.procs = []Proc{codexProc(5001, 1, 120, 1002)}
	h.burnedIn(1002, 24*time.Hour)
	h.pass()
	if _, ok := h.tg.find(FamilyControls); ok {
		t.Fatal("script-only root loaded an enforcing controls policy")
	}
	for _, user := range h.status().UIDs {
		if user.UID == 1002 && (user.State != UIDMonitor || user.Reason != WarnPIDMonitorOnly) {
			t.Fatalf("script-only user has inaccurate enforcement status: %+v", user)
		}
	}
}

func TestReadyScriptUserKeepsMonitorCoverage(t *testing.T) {
	h := newHarness(t, enforceIntent(Digest()), baseTargets)
	h.procs = twoUserProcs()
	h.pass()
	h.burnedIn(1001, 24*time.Hour)
	h.burnedIn(1002, 24*time.Hour)
	h.pass()
	controls, enforcing := h.tg.find(FamilyControls)
	burnin, monitoring := h.tg.find(FamilyBurnin)
	if !enforcing || !controls.Mode.Enforcing() || !monitoring || burnin.Mode != LoadedMonitor {
		t.Fatalf("missing safe enforcement and script monitoring: controls %+v burnin %+v", controls, burnin)
	}
	var found bool
	for _, user := range h.status().UIDs {
		if user.UID == 1002 {
			found = true
			if user.State != UIDMonitor || user.Reason != WarnPIDMonitorOnly {
				t.Fatalf("script user is not reported as monitor-only: %+v", user)
			}
		}
	}
	if !found {
		t.Fatal("script user missing from status")
	}
}
