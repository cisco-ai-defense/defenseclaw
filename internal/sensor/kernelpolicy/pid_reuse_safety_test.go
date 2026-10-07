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
	if compiled.Anchored[1002] != 0 {
		t.Fatalf("reported enforcing anchors for script-only root: %v", compiled.Anchored)
	}

	monitor := w.compile(Input{Controls: &Scope{Mode: PolicyMonitor, UIDs: []int{1002}}, Roots: roots.Roots})
	policy := policyOf(t, monitor, FamilyControls)
	if len(policy.PIDs) != 1 || policy.PIDs[0] != 5001 {
		t.Fatalf("monitor lost its live-root measurement: %v", policy.PIDs)
	}
}

func TestScriptOnlyUserIsReportedInactiveAfterBurnIn(t *testing.T) {
	h := newHarness(t, enforceIntent(Digest(), "codex"), baseTargets)
	h.procs = []Proc{codexProc(5001, 1, 120, 1002)}
	h.burnedIn(1002, 24*time.Hour)
	h.pass()
	if _, ok := h.tg.find(FamilyControls); ok {
		t.Fatal("script-only root loaded an enforcing controls policy")
	}
	for _, user := range h.status().UIDs {
		if user.UID == 1002 && (user.State != UIDInactive || user.Reason != ReasonNoAnchors) {
			t.Fatalf("script-only user has inaccurate enforcement status: %+v", user)
		}
	}
}
