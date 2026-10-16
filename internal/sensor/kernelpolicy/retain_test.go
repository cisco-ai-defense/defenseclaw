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
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const aliceClaude102 = "/home/alice/.local/share/claude/versions/2.1.102"

// controlsNames are the controls-family names Tetragon holds now.
func controlsNames(h *harness) []string {
	var out []string
	for _, name := range h.tg.names() {
		if family, _ := FamilyOfName(name); family == FamilyControls {
			out = append(out, name)
		}
	}
	return out
}

func policyStatus(h *harness, name string) PolicyStatus {
	for _, p := range h.status().Policies {
		if p.Name == name {
			return p
		}
	}
	return PolicyStatus{}
}

// updatedMidSession returns a harness in enforce where alice's Claude Code
// session 4010 started after the enforcing controls policy (old) loaded, and
// then updated itself: a new version in the versions directory is a new
// binaries anchor, so the plan wants a new controls policy (current) that
// loaded after the session started.
func updatedMidSession(t *testing.T) (h *harness, old, current string) {
	t.Helper()
	h = enforcing(t)
	old = mustName(t, h.status(), FamilyControls)
	h.procs = []Proc{nativeProc(4010, 1, 300, 1001, aliceClaudeNew), codexProc(5001, 1, 120, 1002)}
	h.pass()
	if calls := mutations(h.tg.take()); len(calls) != 0 {
		t.Fatalf("a session start changed Tetragon: %v", calls)
	}
	h.w.fs.elf(aliceClaude102)
	h.now = h.now.Add(time.Minute)
	h.pass()
	for _, name := range controlsNames(h) {
		if name != old {
			current = name
		}
	}
	if current == "" {
		t.Fatalf("the update did not load a new controls policy: %v", h.tg.names())
	}
	return h, old, current
}

// #1156: an agent's own update replaced the controls policy and deleted the
// one the running session started under, so the session was only monitored
// until it restarted. The replaced policy now stays loaded and enforcing
// while a session only it marked is alive, survives a helper restart, is
// counted in the status and its hits in the tally, and goes on the last such
// session's exit.
func TestAgentUpdateKeepsTheControlsOfTheRunningSession(t *testing.T) {
	h, old, current := updatedMidSession(t)
	calls := h.tg.take()
	if indexOf(calls, "delete:"+old) >= 0 {
		t.Fatalf("the update deleted %s under its running session: %v", old, calls)
	}
	for _, name := range []string{old, current} {
		if p, ok := h.tg.policies[name]; !ok || !p.Mode.Enforcing() || p.State != StateEnabled {
			t.Fatalf("%s = %+v; both controls must enforce", name, p)
		}
	}
	if st := policyStatus(h, old); st.RetainedSessions != 1 || st.DesiredMode != PolicyEnforce {
		t.Fatalf("status of the kept policy %+v", st)
	}
	if st := policyStatus(h, current); st.RetainedSessions != 0 || st.DesiredMode != PolicyEnforce {
		t.Fatalf("status of the replacement %+v", st)
	}
	if warning, observed := predating(h); warning != "" || len(observed) != 0 {
		t.Fatalf("the kept session is reported as not enforced: %q %+v", warning, observed)
	}
	if state := userState(h, 1001); state.State != UIDEnforcing {
		t.Fatalf("alice = %+v", state)
	}
	if !h.status().InSync {
		t.Fatalf("a kept policy is not drift: %+v", h.status().Warnings)
	}
	// The kept policy's denials count once, against their control.
	h.ctl.RecordHit(Hit{Policy: old, UID: 1001, Path: "/home/alice/.ssh/id_ed25519", Binary: "/usr/bin/cat"})
	if got := h.status().BurnIn.UIDs["1001"].Blocked["kernel.ssh_private_key_read"]; got == nil || got.Count != 1 {
		t.Fatalf("hit of the kept policy: %+v", h.status().BurnIn.UIDs["1001"].Blocked)
	}
	if h.status().HitTotals["blocked_total"] != 1 {
		t.Fatalf("totals %v", h.status().HitTotals)
	}

	// The anchor is in the state file, so a restarted helper keeps it too
	// and attributes its hits.
	data, err := os.ReadFile(h.dirs.StateFile())
	if err != nil {
		t.Fatal(err)
	}
	var file FileState
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if a := file.Applied[old]; a.BinaryUID != 1001 || !containsStr(a.Binaries, aliceClaudeNew) || a.LoadTicks == 0 {
		t.Fatalf("applied record of the kept policy %+v", a)
	}
	h.start(h.intent)
	h.pass()
	if calls := mutations(h.tg.take()); len(calls) != 0 {
		t.Fatalf("a restarted helper changed Tetragon: %v", calls)
	}
	if st := policyStatus(h, old); st.RetainedSessions != 1 {
		t.Fatalf("after a helper restart: %+v", st)
	}
	h.ctl.RecordHit(Hit{Policy: old, UID: 1001, Path: "/home/alice/.ssh/id_ed25519", Binary: "/usr/bin/cat"})
	if got := h.status().BurnIn.UIDs["1001"].Blocked["kernel.ssh_private_key_read"]; got == nil || got.Count != 2 {
		t.Fatalf("hit of the kept policy after a restart: %+v", h.status().BurnIn.UIDs["1001"].Blocked)
	}

	// A session started after the replacement loaded is the replacement's;
	// it does not keep the old policy.
	h.procs = append(h.procs, nativeProc(4020, 1, 400, 1001, aliceClaude102))
	h.pass()
	if st := policyStatus(h, old); st.RetainedSessions != 1 || indexOf(h.tg.take(), "delete:") >= 0 {
		t.Fatalf("a new session changed what is kept: %+v", st)
	}
	// The last session the old policy marked exits: it goes.
	h.procs = []Proc{nativeProc(4020, 1, 400, 1001, aliceClaude102), codexProc(5001, 1, 120, 1002)}
	h.pass()
	if calls := mutations(h.tg.take()); len(calls) != 1 || calls[0] != "delete:"+old {
		t.Fatalf("calls after the last kept session exited = %v, want only the delete of %s", calls, old)
	}
	if contains(h.loadedFile(), old) || policyStatus(h, old).Name != "" {
		t.Fatalf("%s is still recorded", old)
	}
	if p, ok := h.tg.policies[current]; !ok || !p.Mode.Enforcing() {
		t.Fatalf("the replacement %+v", p)
	}
}

// A pause keeps nothing it replaced: the demote step moves both controls
// policies to monitor and the replaced one is deleted.
func TestAPauseDeletesAReplacedControlsPolicy(t *testing.T) {
	h, old, current := updatedMidSession(t)
	h.tg.take()
	h.pause(time.Hour)
	h.pass()
	calls := mutations(h.tg.take())
	if indexOf(calls, "delete:"+old) < 0 || indexOf(calls, "configure:"+current+":monitor") < 0 {
		t.Fatalf("pause calls = %v", calls)
	}
	for _, call := range calls {
		if enforcingControls(call) {
			t.Fatalf("call %s while paused", call)
		}
	}
	if _, ok := h.tg.policies[old]; ok {
		t.Fatalf("%s still loaded while paused", old)
	}
}

// A failed replacement (failSafe) keeps nothing either: every controls
// policy goes to monitor, and the next pass that works deletes the replaced
// one instead of putting it back in enforce.
func TestAFailedReplacementStopsKeepingAControlsPolicy(t *testing.T) {
	h, old, _ := updatedMidSession(t)
	h.tg.take()
	h.tg.failAll = true
	h.w.fs.elf("/home/alice/.local/share/claude/versions/2.1.103") // another new anchor
	h.pass()
	if p := h.tg.policies[old]; p == nil || p.Mode.Enforcing() {
		t.Fatalf("after a failed replacement %s = %+v, want monitor", old, p)
	}
	if st := policyStatus(h, old); st.RetainedSessions != 0 {
		t.Fatalf("a failed pass still keeps %s: %+v", old, st)
	}
	h.tg.take()
	h.tg.failAll = false
	h.pass()
	calls := mutations(h.tg.take())
	if indexOf(calls, "delete:"+old) < 0 {
		t.Fatalf("calls after the recovery = %v; %s must go", calls, old)
	}
	for _, call := range calls {
		if strings.HasPrefix(call, "configure:"+old) {
			t.Fatalf("the replaced policy was put back: %s", call)
		}
	}
}

// The user controls its versions directory, so it can change the anchor
// while sessions run: at most maxRetainedControls replaced policies stay,
// the newest, and the sessions of the others are reported as predating.
func TestKeptControlsPoliciesAreBounded(t *testing.T) {
	h, _, _ := updatedMidSession(t)
	load := uint64(300) // the replacement loaded with the session at 300 the newest process
	for i := 0; i < maxRetainedControls+1; i++ {
		// A session under the newest policy, then another anchor change that
		// loads after it started.
		h.procs = append(h.procs, nativeProc(4100+i, 1, load+50, 1001, aliceClaudeNew))
		h.pass()
		h.w.fs.elf("/home/alice/.local/share/claude/versions/2.2." + string(rune('0'+i)))
		load += 100
		h.procs = append(h.procs, Proc{PID: 9000 + i, PPID: 1, StartTicks: load, UID: 1002, EUID: 1002, Exe: "/usr/bin/true", Host: true})
		h.pass()
	}
	kept := 0
	for _, p := range h.status().Policies {
		if p.RetainedSessions > 0 {
			kept++
		}
	}
	if kept != maxRetainedControls {
		t.Fatalf("%d replaced policies kept, want %d: %+v", kept, maxRetainedControls, h.status().Policies)
	}
	if loaded := len(controlsNames(h)); loaded != maxRetainedControls+1 {
		t.Fatalf("%d controls policies loaded, want %d kept and the current one: %v", loaded, maxRetainedControls, h.tg.names())
	}
	if warning, _ := predating(h); warning == "" {
		t.Fatal("the sessions of the policies not kept are not reported")
	}
}

// A user the plan no longer denies for through a binaries anchor keeps
// nothing: the mode leaves enforce.
func TestLeavingEnforceKeepsNoReplacedControls(t *testing.T) {
	h, old, _ := updatedMidSession(t)
	h.tg.take()
	h.start(observeIntent())
	h.pass()
	if _, ok := h.tg.policies[old]; ok {
		t.Fatalf("%s still loaded in observe: %v", old, h.tg.names())
	}
	for _, name := range controlsNames(h) {
		if p := h.tg.policies[name]; p.Mode.Enforcing() {
			t.Fatalf("%s enforces in observe", name)
		}
	}
}

// #1156 after a load with no enrolled process alive. The process scan right
// after such a load finds nothing, which proves that every later session
// started after it and was marked. The load time used to be 0 (not known)
// then, so the policy counted as having marked nobody and the first agent
// update after it deleted the policy under the running session. The common
// case is a boot: Tetragon starts with no policies and the helper loads them
// again before anyone logs in.
func TestAgentUpdateAfterALoadWithNoSessionKeepsTheControls(t *testing.T) {
	cases := map[string]func(t *testing.T) *harness{
		"boot before login": func(t *testing.T) *harness {
			h := enforcing(t)
			h.tg.restart()
			h.procs = nil
			h.start(h.intent) // the helper starts with the boot too
			h.pass()
			return h
		},
		"enforce before any session": func(t *testing.T) *harness {
			intent := enforceIntent(Digest())
			intent.BurnIn = 0
			h := newHarness(t, intent, baseTargets)
			h.pass()
			return h
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			old := mustName(t, h.status(), FamilyControls)
			if p := h.tg.policies[old]; p == nil || !p.Mode.Enforcing() {
				t.Fatalf("controls after the load = %+v, want enforce", p)
			}
			loadTicks := h.status().Applied[old].LoadTicks
			h.tg.take()
			// The user logs in and starts Claude Code.
			h.procs = []Proc{nativeProc(4010, 1, 300, 1001, aliceClaudeNew), codexProc(5001, 1, 320, 1002)}
			h.pass()
			if calls := h.tg.take(); indexOf(calls, "delete:") >= 0 || len(controlsNames(h)) != 1 {
				t.Fatalf("a session start replaced the controls: %v, loaded %v", mutations(calls), h.tg.names())
			}
			if warning, observed := predating(h); warning != "" || len(observed) != 0 {
				t.Fatalf("a session started after the load is reported as predating it: %q %+v", warning, observed)
			}
			// Claude Code updates itself.
			h.w.fs.elf(aliceClaude102)
			h.now = h.now.Add(time.Minute)
			h.pass()
			calls := mutations(h.tg.take())
			if indexOf(calls, "add:defenseclaw-controls-") < 0 || indexOf(calls, "delete:"+old) >= 0 {
				t.Fatalf("calls after the update = %v, want the replacement added and %s kept", calls, old)
			}
			if p := h.tg.policies[old]; p == nil || !p.Mode.Enforcing() || p.State != StateEnabled {
				t.Fatalf("%s after the update = %+v, want enforcing", old, p)
			}
			if st := policyStatus(h, old); st.RetainedSessions != 1 || st.DesiredMode != PolicyEnforce {
				t.Fatalf("status of the kept policy %+v", st)
			}
			if warning, observed := predating(h); warning != "" || len(observed) != 0 {
				t.Fatalf("the running session is reported as not enforced: %q %+v", warning, observed)
			}
			// The session exits: the kept policy goes.
			h.procs = []Proc{codexProc(5001, 1, 320, 1002)}
			h.pass()
			if calls := mutations(h.tg.take()); len(calls) != 1 || calls[0] != "delete:"+old {
				t.Fatalf("calls after the session exited = %v, want only the delete of %s", calls, old)
			}
			if loadTicks != 1 {
				t.Fatalf("load ticks of a load with no process alive = %d, want 1 (0 is not known)", loadTicks)
			}
		})
	}
}

// A load whose process scan failed has no known load time (0): it is not
// taken as having marked any session, so the first agent update replaces it
// as before and the running session is reported as predating the controls.
func TestALoadWithAFailedScanMarksNothing(t *testing.T) {
	h := enforcing(t)
	h.tg.restart()
	h.procs = nil
	h.start(h.intent)
	scan := h.ctl.cfg.Procs
	h.ctl.cfg.Procs = func(func(int) bool) ([]Proc, error) { return nil, errors.New("/proc is not readable") }
	h.pass()
	old := mustName(t, h.status(), FamilyControls)
	if p := h.tg.policies[old]; p == nil || !p.Mode.Enforcing() {
		t.Fatalf("controls after the load = %+v, want enforce", p)
	}
	if got := h.status().Applied[old].LoadTicks; got != 0 {
		t.Fatalf("load ticks after a failed scan = %d, want 0 (not known)", got)
	}
	h.ctl.cfg.Procs = scan
	h.procs = []Proc{nativeProc(4010, 1, 300, 1001, aliceClaudeNew), codexProc(5001, 1, 320, 1002)}
	h.pass()
	h.tg.take()
	h.w.fs.elf(aliceClaude102)
	h.now = h.now.Add(time.Minute)
	h.pass()
	if calls := mutations(h.tg.take()); indexOf(calls, "delete:"+old) < 0 {
		t.Fatalf("calls after the update = %v, want %s replaced", calls, old)
	}
	if warning, _ := predating(h); warning != WarnSessionsPredateControls+":1" {
		t.Fatalf("predating warning %q, want the running session named", warning)
	}
}

// A connector taken out of enforce keeps nothing either: alice's Claude Code
// session was kept by the policy it started under, then the administrator
// enforces only OpenCode. Her controls still deny through a binaries anchor
// (OpenCode's), but not for Claude Code, so the old policy goes.
func TestAConnectorLeavingEnforceKeepsNoReplacedControls(t *testing.T) {
	intent := enforceIntent(Digest(), "claudecode", "opencode")
	intent.BurnIn = 0
	h := newHarness(t, intent, baseTargets+"- user: alice\n  uid: 1001\n  user_home: /home/alice\n  connector: opencode\n")
	h.w.fs.elf("/home/alice/.opencode/bin/opencode")
	h.procs = []Proc{codexProc(5001, 1, 100, 1002)}
	h.pass()
	old := mustName(t, h.status(), FamilyControls)
	h.procs = append(h.procs, nativeProc(4010, 1, 300, 1001, aliceClaudeNew))
	h.pass()
	h.w.fs.elf(aliceClaude102)
	h.now = h.now.Add(time.Minute)
	h.pass()
	if st := policyStatus(h, old); st.RetainedSessions != 1 {
		t.Fatalf("the update did not keep %s for the session: %+v", old, st)
	}
	h.tg.take()
	opencode := enforceIntent(Digest(), "opencode")
	opencode.BurnIn = 0
	h.start(opencode)
	h.pass()
	if calls := mutations(h.tg.take()); indexOf(calls, "delete:"+old) < 0 {
		t.Fatalf("calls after Claude Code left enforce = %v, want %s deleted", calls, old)
	}
	if _, ok := h.tg.policies[old]; ok {
		t.Fatalf("%s still loaded for a connector that is no longer enforced: %v", old, h.tg.names())
	}
}
