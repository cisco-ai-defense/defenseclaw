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
	"strings"
	"testing"
	"time"
)

func predating(h *harness) (warning string, observed []Observed) {
	for _, w := range h.status().Warnings {
		if strings.HasPrefix(w, WarnSessionsPredateControls) {
			warning = w
		}
	}
	for _, o := range h.status().Roots.Observed {
		if o.Reason == ReasonPredatesControls {
			observed = append(observed, o)
		}
	}
	return warning, observed
}

func userState(h *harness, uid int) UIDStatus {
	for _, u := range h.status().UIDs {
		if u.UID == uid {
			return u
		}
	}
	return UIDStatus{}
}

// GAP-0053: Tetragon marks an agent's processes for the binaries anchor
// (matchBinaries followChildren) when the agent starts. A session that was
// already running when the enforcing controls loaded is not denied, while
// its user shows as enforcing. Status now names those sessions; a session
// started after the load is covered and is not named.
func TestSessionsThatPredateTheEnforcingControlsAreReported(t *testing.T) {
	h := enforcing(t) // alice's Claude session 4001 was running before the load
	warning, observed := predating(h)
	if warning != WarnSessionsPredateControls+":1" || len(observed) != 1 ||
		observed[0] != (Observed{UID: 1001, Reason: ReasonPredatesControls, Connector: "claudecode", Count: 1}) {
		t.Fatalf("warning %q observed %+v", warning, observed)
	}
	if state := userState(h, 1001); state.State != UIDEnforcing {
		t.Fatalf("alice = %+v; new sessions are still denied", state)
	}
	// The old session ends, a new one starts: it is marked at its start.
	h.procs = []Proc{nativeProc(4010, 1, 300, 1001, aliceClaudeNew), codexProc(5001, 1, 120, 1002)}
	h.pass()
	if warning, observed := predating(h); warning != "" || len(observed) != 0 {
		t.Fatalf("a session started after the load: warning %q observed %+v", warning, observed)
	}
	// A Tetragon restart drops the policy; loaded again, every running
	// session predates it.
	h.tg.restart()
	h.pass()
	if warning, _ := predating(h); warning != WarnSessionsPredateControls+":1" {
		t.Fatalf("after a Tetragon restart: warning %q, want the running session named", warning)
	}
}

// GAP-0053: a pause loaded the monitor render and a resume the enforce
// render again, so Tetragon held a new policy after the resume and every
// session that was denied before the pause could read the key. A pause now
// demotes the enforcing policy in place and a resume promotes it in place.
func TestPauseAndResumeKeepTheEnforcingPolicyAndItsSessions(t *testing.T) {
	h := enforcing(t)
	h.procs = []Proc{nativeProc(4010, 1, 300, 1001, aliceClaudeNew), codexProc(5001, 1, 120, 1002)}
	h.pass()
	first, _ := h.tg.find(FamilyControls)
	h.tg.take()

	h.now = h.now.Add(time.Minute)
	h.pause(time.Hour)
	h.pass()
	calls := mutations(h.tg.take())
	if len(calls) != 1 || calls[0] != "configure:"+first.Name+":monitor" {
		t.Fatalf("pause calls = %v, want only the in-place demotion of %s", calls, first.Name)
	}
	if state := userState(h, 1001); state.State != UIDMonitor || state.Reason != WarnEnforcePaused {
		t.Fatalf("alice while paused = %+v", state)
	}
	st := h.status()
	if !st.InSync || st.Effective != string(ModeObserve) {
		t.Fatalf("paused: in sync %v, effective %s", st.InSync, st.Effective)
	}
	for _, p := range st.Policies {
		if p.Name == first.Name && p.DesiredMode != PolicyMonitor {
			t.Fatalf("paused policy status %+v, want desired monitor", p)
		}
	}
	// A session started while paused is marked too: the policy stays loaded.
	h.procs = append(h.procs, nativeProc(4020, 1, 400, 1001, aliceClaudeNew))
	h.pass()
	for _, call := range h.tg.take() {
		if strings.HasPrefix(call, "add:") || strings.HasPrefix(call, "delete:") || enforcingControls(call) {
			t.Fatalf("call %s while paused", call)
		}
	}

	h.resume()
	h.pass()
	calls = mutations(h.tg.take())
	if len(calls) != 1 || calls[0] != "configure:"+first.Name+":enforce" {
		t.Fatalf("resume calls = %v, want only the in-place promotion of %s", calls, first.Name)
	}
	if state := userState(h, 1001); state.State != UIDEnforcing {
		t.Fatalf("alice after the resume = %+v", state)
	}
	if warning, observed := predating(h); warning != "" || len(observed) != 0 {
		t.Fatalf("after the resume: warning %q observed %+v; the sessions kept their mark", warning, observed)
	}
}
