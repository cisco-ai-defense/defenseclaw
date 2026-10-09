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

// The two limits of enforcement from the security review (numeric pid
// anchors are monitor-only; one binary uid per controls policy) are named
// where they apply, and only there.

const twoNativeTargets = `targets:
- user: alice
  uid: 1001
  user_home: /home/alice
  connector: claudecode
- user: bob
  uid: 1002
  user_home: /home/bob
  connector: claudecode
`

// Decoy path, like the others in world_test.go.
const bobClaude = "/home/bob/.local/share/claude/versions/2.1.101"

func TestPIDNoteOnlyWhenAScriptSessionIsLeftToMonitor(t *testing.T) {
	w := newWorld(t, baseTargets)
	scope := &Scope{Mode: PolicyEnforce, UIDs: []int{1001}}
	native := w.roots(nativeProc(4001, 1, 100, 1001, aliceClaudeNew))
	if c := w.compile(Input{Controls: scope, Roots: native.Roots}); anyContains(c.Notes, WarnPIDMonitorOnly) {
		t.Fatalf("a native session the binaries deny is not monitor-only: %v", c.Notes)
	}
	both := w.roots(nativeProc(4001, 1, 100, 1001, aliceClaudeNew), codexProc(4002, 1, 110, 1001))
	if c := w.compile(Input{Controls: scope, Roots: both.Roots}); !anyContains(c.Notes, WarnPIDMonitorOnly) {
		t.Fatalf("an npm Codex session of an enforced user is matched by pid only and must be named: %v", c.Notes)
	}
}

// GAP-0042: a ready user is enforcing only while a controls policy is
// enabled in enforce mode. When Tetragon refuses to load it, the user stays
// in monitor mode and says why, instead of "enforcing" with nothing denied.
func TestAUserIsEnforcingOnlyWhileTheControlsPolicyLoads(t *testing.T) {
	h := newHarness(t, enforceIntent(Digest()), twoNativeTargets)
	h.procs = []Proc{nativeProc(4001, 1, 100, 1001, aliceClaudeNew)}
	h.tg.loadError = FamilyControls
	h.pass()
	h.burnedIn(1001, 24*time.Hour)
	h.pass()
	if alice := uidStatus(h.status(), 1001); alice.State != UIDMonitor || alice.Reason != WarnPolicyLoadError {
		t.Fatalf("a ready user whose controls policy did not load: %+v", alice)
	}
	if !h.has(WarnPolicyLoadError) {
		t.Fatalf("warnings %v", h.status().Warnings)
	}
}

func TestReadyNativeUserBeyondTheBinaryUIDIsScopeLimited(t *testing.T) {
	h := newHarness(t, enforceIntent(Digest()), twoNativeTargets)
	h.w.fs.elf(bobClaude)
	h.w.fs.symlink("/home/bob/.local/bin/claude", bobClaude)
	h.procs = []Proc{nativeProc(4001, 1, 100, 1001, aliceClaudeNew), nativeProc(5001, 1, 120, 1002, bobClaude)}
	h.pass()
	h.burnedIn(1001, 24*time.Hour)
	h.burnedIn(1002, 24*time.Hour)
	h.pass()
	if alice := uidStatus(h.status(), 1001); alice.State != UIDEnforcing {
		t.Fatalf("the lowest uid with a native install is enforced: %+v", alice)
	}
	if bob := uidStatus(h.status(), 1002); bob.State != UIDMonitor || bob.Reason != WarnBinaryScopeLimited {
		t.Fatalf("the second native user stays in monitor and says why: %+v", bob)
	}
	if !h.has(WarnBinaryScopeLimited) || h.has(WarnPIDMonitorOnly) {
		t.Fatalf("warnings %v", h.status().Warnings)
	}
	if _, ok := h.tg.find(FamilyBurnin); !ok {
		t.Fatalf("the second user's sessions must stay measured by the monitor family: %v", h.tg.names())
	}
}
