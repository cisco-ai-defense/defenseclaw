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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// enforcingControls reports whether a recorded call would make a controls
// policy enforce. Post-only policies have no mode to speak of.
func enforcingControls(call string) bool {
	return strings.Contains(call, "defenseclaw-controls") && strings.HasSuffix(call, ":enforce")
}

func twoUserProcs() []Proc {
	return []Proc{nativeProc(4001, 1, 100, 1001, aliceClaudeNew), codexProc(5001, 1, 120, 1002)}
}

// enforcing returns a harness whose two users finished burn-in and whose
// controls policy is enforcing.
func enforcing(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, enforceIntent(Digest()), baseTargets)
	h.procs = twoUserProcs()
	h.pass() // monitor for everyone
	h.burnedIn(1001, 24*time.Hour)
	h.burnedIn(1002, 24*time.Hour)
	h.pass()
	if p, ok := h.tg.find(FamilyControls); !ok || !p.Mode.Enforcing() {
		t.Fatalf("controls not enforcing: %+v %v", p, h.tg.names())
	}
	h.tg.take()
	return h
}

func TestObserveLoadsPoliciesInMonitorMode(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	h.pass()
	calls := h.tg.take()

	for _, family := range []Family{FamilyObserve, FamilyConnect, FamilyControls} {
		if _, ok := h.tg.find(family); !ok {
			t.Fatalf("%s not loaded: %v", family, h.tg.names())
		}
	}
	if _, ok := h.tg.find(FamilyBurnin); ok {
		t.Fatal("controls-burnin loads only when some users are ready and others are not")
	}
	controls, _ := h.tg.find(FamilyControls)
	if controls.Mode != LoadedMonitor {
		t.Fatalf("controls mode = %s; observe never enforces", controls.Mode)
	}
	// The mode travels in the YAML: the policy is never loaded enforcing and
	// flipped.
	if countCalls(calls, "configure:") != 0 {
		t.Fatalf("calls = %v; a monitor policy must be added as monitor", calls)
	}
	for _, p := range h.status().Policies {
		if got := h.ctl.OwnsPolicy(p.Name, p.Family); !got {
			t.Fatalf("%s is recorded and loaded, but OwnsPolicy says no", p.Name)
		}
		if h.ctl.OwnsPolicy(p.Name, FamilyBurnin) && p.Family != FamilyBurnin {
			t.Fatalf("%s claimed by the wrong family", p.Name)
		}
	}
	if h.ctl.OwnsPolicy("defenseclaw-observe-deadbeef", FamilyObserve) {
		t.Fatal("a name the helper never loaded is not its own")
	}
	if indexOf(calls, "add:defenseclaw-controls-") < 0 || !strings.HasSuffix(calls[indexOf(calls, "add:defenseclaw-controls-")], ":monitor") {
		t.Fatalf("calls = %v", calls)
	}
	// Visibility first: observe is added before the controls.
	if indexOf(calls, "add:defenseclaw-observe-") > indexOf(calls, "add:defenseclaw-controls-") {
		t.Fatalf("observe must load before controls: %v", calls)
	}

	recorded := h.loadedFile()
	if strings.Join(recorded, ",") != strings.Join(h.tg.names(), ",") || len(recorded) != 3 {
		t.Fatalf("tetragon-loaded %v, loaded %v", recorded, h.tg.names())
	}
	state, err := ReadState(h.dirs)
	if err != nil {
		t.Fatal(err)
	}
	if state.KernelPolicy != Digest() || state.Effective != "observe" || !state.Tetragon.Reachable || state.Tetragon.PID != 4242 {
		t.Fatalf("state = %+v", state.FileState)
	}
	if !state.InSync {
		t.Fatal("a pass that loaded everything it planned is in sync")
	}
	if len(state.Policies) != 3 || len(state.Loaded) != 3 {
		t.Fatalf("policies %d loaded %d", len(state.Policies), len(state.Loaded))
	}
	for _, name := range recorded {
		data, err := os.ReadFile(filepath.Join(h.dirs.PolicyCopies(), name+".yaml"))
		if err != nil || !strings.HasPrefix(string(data), "# defenseclaw-derived:") {
			t.Fatalf("policy copy of %s: %v %q", name, err, data)
		}
	}
	// A second pass with nothing changed makes no change.
	h.pass()
	for _, call := range h.tg.take() {
		if strings.HasPrefix(call, "add:") || strings.HasPrefix(call, "delete:") || strings.HasPrefix(call, "configure:") {
			t.Fatalf("idempotent pass made call %s", call)
		}
	}
}

func TestEnforceNeedsTheApprovedDigest(t *testing.T) {
	for _, tc := range []struct {
		name, ack, warning string
	}{
		{"missing", "", WarnEnforceAckMissing},
		{"stale", "sha256:000000000000", WarnEnforceAckStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, enforceIntent(tc.ack), baseTargets)
			h.procs = twoUserProcs()
			h.burnedIn(1001, 48*time.Hour)
			h.burnedIn(1002, 48*time.Hour)
			h.pass()
			controls, ok := h.tg.find(FamilyControls)
			if !ok || controls.Mode != LoadedMonitor {
				t.Fatalf("controls = %+v, want a monitor policy (burn-in alone never enforces)", controls)
			}
			if !h.has(tc.warning) {
				t.Fatalf("warnings = %v, want %s", h.status().Warnings, tc.warning)
			}
			for _, uid := range h.status().UIDs {
				if uid.State == UIDEnforcing {
					t.Fatalf("user %d enforcing without an approval", uid.UID)
				}
			}
		})
	}
}

func TestApprovedButUnmeasuredUsersStayInMonitor(t *testing.T) {
	h := newHarness(t, enforceIntent(Digest()), baseTargets)
	h.procs = twoUserProcs()
	h.pass()
	controls, _ := h.tg.find(FamilyControls)
	if controls.Mode != LoadedMonitor || !h.has(ReasonNoReadyUsers) {
		t.Fatalf("controls %+v warnings %v", controls, h.status().Warnings)
	}
	if _, ok := h.tg.find(FamilyBurnin); ok {
		t.Fatal("no user is ready, so controls-burnin is not loaded")
	}
}

func TestReadyUsersEnforceAndTheRestBurnIn(t *testing.T) {
	h := newHarness(t, enforceIntent(Digest()), baseTargets)
	h.procs = twoUserProcs()
	h.burnedIn(1001, 24*time.Hour)
	h.pass()
	controls, ok1 := h.tg.find(FamilyControls)
	burnin, ok2 := h.tg.find(FamilyBurnin)
	if !ok1 || !ok2 || !controls.Mode.Enforcing() || burnin.Mode != LoadedMonitor {
		t.Fatalf("controls %+v burnin %+v (%v)", controls, burnin, h.tg.names())
	}
	states := map[int]string{}
	for _, u := range h.status().UIDs {
		states[u.UID] = u.State
	}
	if states[1001] != UIDEnforcing || states[1002] != UIDBurnIn {
		t.Fatalf("states = %v", states)
	}
	// Each policy carries only its own users.
	state := h.status()
	var controlsName, burninName string
	for _, p := range state.Policies {
		switch p.Family {
		case FamilyControls:
			controlsName = p.Name
		case FamilyBurnin:
			burninName = p.Name
		}
	}
	for name, uid := range map[string]string{controlsName: `"1001"`, burninName: `"1002"`} {
		data, err := os.ReadFile(filepath.Join(h.dirs.PolicyCopies(), name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		other := `"1002"`
		if uid == `"1002"` {
			other = `"1001"`
		}
		if !strings.Contains(string(data), uid) || strings.Contains(string(data), other) {
			t.Fatalf("%s names the wrong users:\n%s", name, data)
		}
	}
}

func TestPromotionFlipsInPlaceAndScopeChangesAddBeforeDelete(t *testing.T) {
	h := newHarness(t, enforceIntent(Digest()), baseTargets)
	h.procs = twoUserProcs()
	h.pass()
	first, _ := h.tg.find(FamilyControls)
	h.tg.take()

	// Everyone finishes burn-in: the same scope, so the same name, flipped.
	h.burnedIn(1001, 24*time.Hour)
	h.burnedIn(1002, 24*time.Hour)
	h.pass()
	calls := h.tg.take()
	if countCalls(calls, "configure:"+first.Name+":enforce") != 1 || countCalls(calls, "add:") != 0 || countCalls(calls, "delete:") != 0 {
		t.Fatalf("calls = %v, want one in-place flip", calls)
	}

	// A new session changes the pid anchor: a new name, added before the old
	// one is deleted, so the overlap is briefly stricter and never looser.
	h.procs = append(h.procs, codexProc(4100, 1, 200, 1001))
	h.pass()
	calls = h.tg.take()
	add, del := indexOf(calls, "add:defenseclaw-controls-"), indexOf(calls, "delete:"+first.Name)
	if add < 0 || del < 0 || add > del {
		t.Fatalf("calls = %v, want add before delete", calls)
	}
	if !strings.HasSuffix(calls[add], ":enforce") {
		t.Fatalf("the replacement must load enforcing: %v", calls)
	}
	if countCalls(calls, "configure:") != 0 {
		t.Fatalf("no policy may be demoted during a scope change: %v", calls)
	}
	if len(h.tg.names()) != 3 {
		t.Fatalf("loaded %v, want observe, connect and one controls", h.tg.names())
	}
}

func TestTetragonRestartIsReAddedAndIsNotAnOverride(t *testing.T) {
	h := enforcing(t)
	h.tg.restart()
	h.pass()
	calls := h.tg.take()
	if countCalls(calls, "add:") != 3 {
		t.Fatalf("calls = %v, want observe, connect and controls re-added", calls)
	}
	controls, ok := h.tg.find(FamilyControls)
	if !ok || !controls.Mode.Enforcing() {
		t.Fatalf("controls after restart = %+v", controls)
	}
	state := h.status()
	if len(state.Overrides) != 0 {
		t.Fatalf("overrides = %v; a restart is not an operator", state.Overrides)
	}
	seen := false
	for _, ch := range state.Changes {
		if ch.Event == EventTetragonRestarted {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("no tetragon_restarted change: %+v", state.Changes)
	}
}

func TestOperatorMonitorIsNeverRePromoted(t *testing.T) {
	h := enforcing(t)
	controls, _ := h.tg.find(FamilyControls)
	h.tg.setMode(controls.Name, LoadedMonitor) // tetra tracingpolicy set-mode <name> monitor

	h.pass()
	if o, ok := h.status().Overrides[FamilyControls]; !ok || o.Kind != OverrideMonitor {
		t.Fatalf("overrides = %v", h.status().Overrides)
	}
	if !h.has(WarnOperatorOverride) {
		t.Fatalf("warnings = %v", h.status().Warnings)
	}
	// Nothing the helper does afterwards re-enforces: passes, a Tetragon
	// restart, a helper restart.
	stillMonitor := func(when string) {
		t.Helper()
		for _, call := range h.tg.take() {
			if enforcingControls(call) {
				t.Fatalf("%s: call %s re-promotes a policy a human moved to monitor", when, call)
			}
		}
		if p, ok := h.tg.find(FamilyControls); ok && p.Mode.Enforcing() {
			t.Fatalf("%s: controls enforcing again", when)
		}
	}
	stillMonitor("first pass")
	h.pass()
	stillMonitor("second pass")
	h.tg.restart()
	h.pass()
	stillMonitor("after a tetragon restart")
	h.start(h.intent)
	h.pass()
	stillMonitor("after a helper restart")
	if _, ok := h.tg.find(FamilyControls); !ok {
		t.Fatal("the controls policy should be back, in monitor")
	}

	// A new intent (the mode or the approval changes) clears the override.
	h.start(observeIntent())
	if len(h.status().Overrides) != 0 {
		t.Fatalf("overrides survived an intent change: %v", h.status().Overrides)
	}
	h.start(enforceIntent(Digest()))
	h.pass()
	if p, ok := h.tg.find(FamilyControls); !ok || !p.Mode.Enforcing() {
		t.Fatalf("after the intent changed the controls should enforce again: %+v", p)
	}
}

func TestOperatorDeleteIsNeverReAdded(t *testing.T) {
	h := enforcing(t)
	controls, _ := h.tg.find(FamilyControls)
	h.tg.remove(controls.Name) // tetra tracingpolicy delete <name>

	h.pass()
	if o, ok := h.status().Overrides[FamilyControls]; !ok || o.Kind != OverrideDeleted {
		t.Fatalf("overrides = %v", h.status().Overrides)
	}
	absent := func(when string) {
		t.Helper()
		if _, ok := h.tg.find(FamilyControls); ok {
			t.Fatalf("%s: the deleted controls policy came back", when)
		}
	}
	absent("first pass")
	h.pass()
	absent("second pass")
	h.tg.restart()
	h.pass()
	absent("after a tetragon restart")
	if _, ok := h.tg.find(FamilyObserve); !ok {
		t.Fatal("only the deleted family stays away; observe is re-added")
	}
	h.start(h.intent)
	h.pass()
	absent("after a helper restart")

	h.start(observeIntent())
	h.pass()
	if _, ok := h.tg.find(FamilyControls); !ok {
		t.Fatal("an intent change should bring the family back")
	}
}

func TestPauseMovesControlsToMonitorFirstAndSurvivesRestarts(t *testing.T) {
	h := enforcing(t)
	first, _ := h.tg.find(FamilyControls)
	h.pause(time.Hour)
	if !h.ctl.pauseChanged() {
		t.Fatal("the pause file was not noticed")
	}
	h.pass()
	calls := h.tg.take()
	cfg := indexOf(calls, "configure:"+first.Name+":monitor")
	if cfg < 0 {
		t.Fatalf("calls = %v, want the controls flipped to monitor", calls)
	}
	for i, call := range calls {
		if strings.HasPrefix(call, "add:") || strings.HasPrefix(call, "delete:") {
			if i < cfg {
				t.Fatalf("calls = %v; the demotion must come first", calls)
			}
		}
	}
	if p, _ := h.tg.find(FamilyControls); p.Mode.Enforcing() {
		t.Fatal("still enforcing under a pause")
	}
	if !h.has(WarnEnforcePaused) || h.status().Pause == nil || h.status().Pause.Pause == nil {
		t.Fatalf("warnings %v pause %+v", h.status().Warnings, h.status().Pause)
	}

	// While paused a new session renames the policy: it is added in monitor.
	h.procs = append(h.procs, codexProc(4100, 1, 200, 1001))
	h.pass()
	for _, call := range h.tg.take() {
		if strings.HasPrefix(call, "add:defenseclaw-controls-") && !strings.HasSuffix(call, ":monitor") {
			t.Fatalf("call %s loads an enforcing policy under a pause", call)
		}
		if enforcingControls(call) {
			t.Fatalf("call %s under a pause", call)
		}
	}
	// A Tetragon restart and a helper restart change nothing.
	h.tg.restart()
	h.start(h.intent)
	h.pass()
	for _, call := range h.tg.take() {
		if enforcingControls(call) {
			t.Fatalf("call %s after restarts under a pause", call)
		}
	}
	if p, ok := h.tg.find(FamilyControls); !ok || p.Mode.Enforcing() {
		t.Fatalf("controls = %+v", p)
	}

	h.resume()
	if !h.ctl.pauseChanged() {
		t.Fatal("resume not noticed")
	}
	h.pass()
	if p, ok := h.tg.find(FamilyControls); !ok || !p.Mode.Enforcing() {
		t.Fatalf("resume should restore enforcement: %+v", p)
	}
}

// The pause is read again at the moment of every Add and Configure, not only
// at the start of the pass.
func TestPauseAppearingMidPassIsHonoured(t *testing.T) {
	t.Run("add", func(t *testing.T) {
		h := newHarness(t, enforceIntent(Digest()), baseTargets)
		h.procs = twoUserProcs()
		h.burnedIn(1001, 24*time.Hour)
		h.burnedIn(1002, 24*time.Hour)
		armed := true
		h.tg.onList = func() {
			if armed {
				armed = false
				h.pause(time.Hour)
			}
		}
		h.pass()
		for _, call := range h.tg.take() {
			if strings.HasPrefix(call, "add:defenseclaw-controls-") && strings.HasSuffix(call, ":enforce") {
				t.Fatalf("call %s: the pause appeared after planning", call)
			}
		}
		if p, ok := h.tg.find(FamilyControls); !ok || p.Mode.Enforcing() {
			t.Fatalf("controls = %+v", p)
		}
	})
	t.Run("configure", func(t *testing.T) {
		h := newHarness(t, enforceIntent(Digest()), baseTargets)
		h.procs = twoUserProcs()
		h.pass() // monitor
		h.burnedIn(1001, 24*time.Hour)
		h.burnedIn(1002, 24*time.Hour)
		armed := true
		h.tg.onList = func() {
			if armed {
				armed = false
				h.pause(time.Hour)
			}
		}
		h.tg.take()
		h.pass()
		for _, call := range h.tg.take() {
			if enforcingControls(call) {
				t.Fatalf("call %s: the pause appeared after planning", call)
			}
		}
	})
}

func TestUntrustedPauseFileKeepsEnforcementOff(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a non-root owner")
	}
	h := enforcing(t)
	h.writeRaw(h.dirs.Pause(), `{"until":"2099-01-01T00:00:00Z"}`)
	saved := pauseFileTrusted
	pauseFileTrusted = rootOwnedPrivate // the real rule: root owns it
	t.Cleanup(func() { pauseFileTrusted = saved })
	state := ReadPause(h.dirs, h.now)
	if state.Invalid == "" || !state.Active() {
		t.Fatalf("a pause file not owned by root must count as a pause: %+v", state)
	}
	h.pass()
	if p, _ := h.tg.find(FamilyControls); p.Mode.Enforcing() {
		t.Fatal("an unreadable pause file must fail toward monitor")
	}
	if !h.has(WarnPauseInvalid) {
		t.Fatalf("warnings = %v", h.status().Warnings)
	}
}

func TestUntilRebootPauseLivesInTheRuntimeDirectory(t *testing.T) {
	h := enforcing(t)
	p, err := NewPause(h.now, 0, true, 0, "incident")
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePause(h.dirs, p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.dirs.RuntimePause()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.dirs.Pause()); !os.IsNotExist(err) {
		t.Fatal("an until-reboot pause must not survive a reboot")
	}
	if !ReadPause(h.dirs, h.now.Add(1000*time.Hour)).Active() {
		t.Fatal("an until-reboot pause never expires on its own")
	}
	// A timed pause replaces it, and expires.
	timed, _ := NewPause(h.now, time.Hour, false, 0, "")
	if err := WritePause(h.dirs, timed); err != nil {
		t.Fatal(err)
	}
	if ReadPause(h.dirs, h.now.Add(2*time.Hour)).Active() {
		t.Fatal("a timed pause must expire")
	}
	if _, err := NewPause(h.now, 8*24*time.Hour, false, 0, ""); err == nil {
		t.Fatal("the longest pause is seven days")
	}
	if _, err := NewPause(h.now, -time.Hour, false, 0, ""); err == nil {
		t.Fatal("a negative pause")
	}
	if _, err := NewPause(h.now, time.Hour, false, 0, "bad\x00reason"); err == nil {
		t.Fatal("a non-printable reason")
	}
}

func TestKeepSensorsOnExitCapsAtMonitor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		agent func(*Agent)
	}{
		{"true", func(a *Agent) { a.KeepSensorsOnExit = true }},
		{"unreadable", func(a *Agent) { a.KeepSensorsOnExitKnown = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, enforceIntent(Digest()), baseTargets)
			tc.agent(&h.tg.agent)
			h.procs = twoUserProcs()
			h.burnedIn(1001, 24*time.Hour)
			h.burnedIn(1002, 24*time.Hour)
			h.pass()
			if p, ok := h.tg.find(FamilyControls); !ok || p.Mode.Enforcing() {
				t.Fatalf("controls = %+v", p)
			}
			if !h.has(WarnPersistentSensors) {
				t.Fatalf("warnings = %v", h.status().Warnings)
			}
		})
	}
}

func TestUnsupportedTetragonAndMissingLSM(t *testing.T) {
	t.Run("1.6", func(t *testing.T) {
		h := newHarness(t, observeIntent(), baseTargets)
		h.tg.agent.Version = "1.6.0"
		h.procs = twoUserProcs()
		h.pass()
		if len(h.tg.names()) != 0 || !h.has(WarnUnsupportedVersion) {
			t.Fatalf("loaded %v warnings %v", h.tg.names(), h.status().Warnings)
		}
		for _, call := range h.tg.take() {
			if strings.HasPrefix(call, "add:") {
				t.Fatalf("call %s on a Tetragon that observe does not support", call)
			}
		}
	})
	t.Run("no pid", func(t *testing.T) {
		h := newHarness(t, observeIntent(), baseTargets)
		h.tg.agent.PID = 0
		h.pass()
		if len(h.tg.names()) != 0 || !h.has(ReasonIdentityUnknown) {
			t.Fatalf("loaded %v warnings %v", h.tg.names(), h.status().Warnings)
		}
	})
	t.Run("no lsm", func(t *testing.T) {
		h := newHarness(t, observeIntent(), baseTargets)
		h.tg.agent.LSM = false
		h.procs = twoUserProcs()
		h.pass()
		if _, ok := h.tg.find(FamilyConnect); !ok {
			t.Fatal("the kprobe policy does not need the LSM")
		}
		if _, ok := h.tg.find(FamilyObserve); ok {
			t.Fatal("file policies cannot load without the BPF LSM")
		}
		if _, ok := h.tg.find(FamilyControls); ok || !h.has(WarnLSMUnavailable) {
			t.Fatalf("warnings %v", h.status().Warnings)
		}
	})
}

func TestFailedAddLeavesEnforcingPoliciesInMonitor(t *testing.T) {
	h := enforcing(t)
	h.tg.failAll = true
	h.procs = append(h.procs, codexProc(4100, 1, 200, 1001)) // a new pid anchor -> new name
	h.pass()
	if p, ok := h.tg.find(FamilyControls); !ok || p.Mode.Enforcing() {
		t.Fatalf("controls = %+v; a failed reconcile must leave monitor", p)
	}
	if h.status().InSync {
		t.Fatal("a failed reconcile is not in sync")
	}
	if !h.has(WarnReconcileFailed) {
		t.Fatalf("warnings = %v", h.status().Warnings)
	}
	for _, call := range h.tg.take() {
		if strings.HasPrefix(call, "delete:") {
			t.Fatalf("call %s after a failed add; the old policy stays", call)
		}
	}
	// The name that failed to load is not recorded as loaded.
	if len(h.loadedFile()) != len(h.tg.names()) {
		t.Fatalf("recorded %v, loaded %v", h.loadedFile(), h.tg.names())
	}
	// And a later pass does not mistake the missing name for an operator.
	h.tg.failAll = false
	h.pass()
	if len(h.status().Overrides) != 0 {
		t.Fatalf("overrides = %v", h.status().Overrides)
	}
}

func TestHelperRestartResumesWithoutTouchingTetragon(t *testing.T) {
	h := enforcing(t)
	h.start(h.intent)
	h.pass()
	for _, call := range h.tg.take() {
		if strings.HasPrefix(call, "add:") || strings.HasPrefix(call, "delete:") || strings.HasPrefix(call, "configure:") {
			t.Fatalf("a restarted helper changed Tetragon: %s", call)
		}
	}
	if p, ok := h.tg.find(FamilyControls); !ok || !p.Mode.Enforcing() {
		t.Fatalf("controls = %+v", p)
	}
}

func TestAStaleAckDemotesARunningEnforcer(t *testing.T) {
	h := enforcing(t)
	// A new build changes kernel_policy: the old ack no longer matches.
	h.start(enforceIntent("sha256:000000000000"))
	h.pass()
	calls := h.tg.take()
	if countCalls(calls, "configure:") != 1 || !strings.HasSuffix(calls[indexOf(calls, "configure:")], ":monitor") {
		t.Fatalf("calls = %v, want the controls demoted to monitor", calls)
	}
	if p, _ := h.tg.find(FamilyControls); p.Mode.Enforcing() || !h.has(WarnEnforceAckStale) {
		t.Fatalf("controls %+v warnings %v", p, h.status().Warnings)
	}
}

func TestOnlyActionConnectorsAreAnchoredForEnforcement(t *testing.T) {
	h := newHarness(t, enforceIntent(Digest(), "claudecode"), baseTargets)
	h.procs = twoUserProcs()
	h.burnedIn(1001, 24*time.Hour)
	h.burnedIn(1002, 24*time.Hour)
	h.pass()
	state := h.status()
	states := map[int]UIDStatus{}
	for _, u := range state.UIDs {
		states[u.UID] = u
	}
	if states[1001].State != UIDEnforcing {
		t.Fatalf("alice has an action connector: %+v", states[1001])
	}
	if states[1002].State != UIDInactive || states[1002].Reason != ReasonGuardrailObserve {
		t.Fatalf("bob only has a codex guardrail in observe mode: %+v", states[1002])
	}
	data, _ := os.ReadFile(filepath.Join(h.dirs.PolicyCopies(), mustName(t, state, FamilyControls)+".yaml"))
	if strings.Contains(string(data), "5001") || strings.Contains(string(data), `"1002"`) {
		t.Fatalf("a connector in observe mode was anchored:\n%s", data)
	}
	seen := false
	for _, o := range state.Roots.Observed {
		if o.Reason == ReasonGuardrailObserve && o.Connector == "codex" && o.UID == 1002 {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("observed-only = %+v, want bob's codex session listed as guardrail_observe", state.Roots.Observed)
	}
	if !h.has(WarnGuardrailObserve) {
		t.Fatalf("warnings = %v", state.Warnings)
	}
}

func mustName(t *testing.T, state State, family Family) string {
	t.Helper()
	for _, p := range state.Policies {
		if p.Family == family {
			return p.Name
		}
	}
	t.Fatalf("no %s policy in %+v", family, state.Policies)
	return ""
}

func TestForeignNamesAreReportedAndNeverTouched(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	h.tg.addForeign("defenseclaw-controls-deadbeef") // shaped like ours, never recorded
	h.tg.addForeign("customer-tcp-policy")
	h.pass()
	if !h.has(WarnForeignName) {
		t.Fatalf("warnings = %v", h.status().Warnings)
	}
	// Even when the mode goes to off and everything of ours is retired.
	h.start(Intent{Mode: ModeOff})
	if err := h.ctl.retireOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.tg.names(), ","); got != "customer-tcp-policy,defenseclaw-controls-deadbeef" {
		t.Fatalf("remaining = %s; only the recorded names may be deleted", got)
	}
}

func TestApprovedUserWithNothingToAnchorIsInactive(t *testing.T) {
	h := newHarness(t, enforceIntent(Digest()), `targets:
- user: carol
  uid: 1003
  user_home: /home/carol
  connector: claudecode
`)
	h.burnedIn(1003, 24*time.Hour)
	h.pass()
	if _, ok := h.tg.find(FamilyControls); ok {
		t.Fatal("a controls policy with nothing to anchor to")
	}
	u := uidStatus(h.status(), 1003)
	if u.State != UIDInactive || u.Reason != ReasonNoAnchors {
		t.Fatalf("carol = %+v", u)
	}
	if !h.has(WarnEnforceInactive) || !h.has("kernel_enforce_inactive: no anchors") {
		t.Fatalf("warnings = %v", h.status().Warnings)
	}
	for _, name := range h.tg.names() {
		data, _ := os.ReadFile(filepath.Join(h.dirs.PolicyCopies(), name+".yaml"))
		if strings.Contains(string(data), "Override") {
			t.Fatalf("%s carries an Override with no anchor", name)
		}
	}
	// A session appears: the controls load.
	h.w.fs.elf("/home/carol/.local/share/claude/versions/2.1.100")
	h.pass()
	if p, ok := h.tg.find(FamilyControls); !ok || !p.Mode.Enforcing() {
		t.Fatalf("controls after an install appeared: %+v", p)
	}
	if u := uidStatus(h.status(), 1003); u.State != UIDEnforcing {
		t.Fatalf("carol = %+v", u)
	}
}

func TestAStaleAckIsRecordedOnceAsAChange(t *testing.T) {
	h := enforcing(t)
	h.start(enforceIntent("sha256:000000000000"))
	h.pass()
	h.pass()
	count := 0
	for _, ch := range h.status().Changes {
		if ch.Event == EventAckStale {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("ack_stale recorded %d times", count)
	}
}

func TestHitsAreAttributedAfterAHelperRestart(t *testing.T) {
	h := enforcing(t)
	controls, _ := h.tg.find(FamilyControls)
	h.start(h.intent)
	h.pass() // adopts the loaded policy without re-adding it
	h.ctl.RecordHit(Hit{Policy: controls.Name, UID: 1001, Path: "/home/alice/.ssh/id_ed25519", Binary: "/usr/bin/cat"})
	h.ctl.RecordHit(Hit{Policy: controls.Name, UID: 1001, Path: "/home/alice/.config/autostart/evil.desktop", Binary: "/usr/bin/tee"})
	rec := h.status().BurnIn.UIDs["1001"]
	if rec.Blocked["kernel.ssh_private_key_read"] == nil || rec.Blocked["kernel.persistence_write"] == nil {
		t.Fatalf("hits were not attributed to their controls: %+v", rec.Blocked)
	}
}

func TestAnAdoptedPolicyIsNotMistakenForAnOperator(t *testing.T) {
	h := enforcing(t)
	// The helper died between recording a call and finishing it: the state has
	// no Applied entry for a policy that is loaded and recorded.
	controls, _ := h.tg.find(FamilyControls)
	delete(h.ctl.st.Applied, controls.Name)
	h.ctl.persist()
	h.start(h.intent)
	h.pass()
	h.pass()
	if len(h.status().Overrides) != 0 {
		t.Fatalf("overrides = %v", h.status().Overrides)
	}
	if _, ok := h.status().Applied[controls.Name]; !ok {
		t.Fatal("the loaded policy was not adopted")
	}
}

func TestOperatorDisablingTheControlsCountsAsAStop(t *testing.T) {
	h := enforcing(t)
	controls, _ := h.tg.find(FamilyControls)
	h.tg.mu.Lock()
	h.tg.policies[controls.Name].State = StateDisabled
	h.tg.mu.Unlock()
	h.pass()
	if o, ok := h.status().Overrides[FamilyControls]; !ok || o.Kind != OverrideMonitor {
		t.Fatalf("overrides = %v; a disabled controls policy is a human's stop", h.status().Overrides)
	}
	for _, call := range h.tg.take() {
		if enforcingControls(call) {
			t.Fatalf("call %s re-enforces a policy the operator disabled", call)
		}
	}
}

// The event mapper asks the controller whether a controls policy enforces:
// the answer changes at the helper's own call, not at the next listing.
func TestPolicyModeFollowsTheHelpersOwnCalls(t *testing.T) {
	h := enforcing(t)
	controls, _ := h.tg.find(FamilyControls)
	mode, at, ok := h.ctl.PolicyMode(controls.Name)
	if !ok || mode != "enforce" {
		t.Fatalf("enforcing controls: %q %v", mode, ok)
	}
	h.now = h.now.Add(time.Minute)
	h.pause(time.Hour)
	h.pass()
	mode, demoted, ok := h.ctl.PolicyMode(controls.Name)
	if !ok || mode != "monitor" || !demoted.After(at) {
		t.Fatalf("after a pause: %q at %v (before %v) %v", mode, demoted, at, ok)
	}
	if _, _, ok := h.ctl.PolicyMode("defenseclaw-controls-ffffffff"); ok {
		t.Fatal("a name the helper never loaded has no mode")
	}
}
