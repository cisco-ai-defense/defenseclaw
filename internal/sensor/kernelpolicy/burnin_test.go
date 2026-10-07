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

func (h *harness) covered(uid int) time.Duration {
	h.ctl.tallyMu.Lock()
	defer h.ctl.tallyMu.Unlock()
	return h.ctl.burn.Covered(uid)
}

func TestCoveredTimeAccruesOnlyWhileEverythingHolds(t *testing.T) {
	h := newHarness(t, enforceIntent(Digest()), baseTargets)
	h.procs = twoUserProcs()
	h.pass() // policies loaded, roots anchored
	minute := time.Minute

	// Connected, lossless, enabled, a root alive: a covered minute.
	h.accrueTick()
	if got := h.covered(1001); got != minute {
		t.Fatalf("covered = %v, want one minute", got)
	}
	// A throttle or rate-limit notice: that minute does not count.
	h.ctl.RecordLoss()
	h.ctl.accrue()
	if got := h.covered(1001); got != minute {
		t.Fatalf("covered = %v after a loss signal", got)
	}
	h.ctl.accrue() // the flag was consumed; this one counts
	if got := h.covered(1001); got != 2*minute {
		t.Fatalf("covered = %v", got)
	}
	// The stream is down: nothing accrues, a Tetragon outage accrues nothing.
	h.ctl.SetStream(false)
	h.ctl.accrue()
	h.ctl.accrue()
	if got := h.covered(1001); got != 2*minute {
		t.Fatalf("covered = %v with the stream down", got)
	}
	h.ctl.SetStream(true)
	h.ctl.accrue() // consumes the stream-change flag
	h.ctl.accrue()
	if got := h.covered(1001); got != 3*minute {
		t.Fatalf("covered = %v", got)
	}
	// A pause counts as no covered time.
	h.pause(time.Hour)
	h.ctl.accrue()
	if got := h.covered(1001); got != 3*minute {
		t.Fatalf("covered = %v under a pause", got)
	}
	h.resume()
	// No anchored root alive (an idle host): nothing.
	h.procs = nil
	h.ctl.rescan()
	before := h.covered(1001)
	h.ctl.accrue()
	if got := h.covered(1001); got != before {
		t.Fatalf("covered grew on an idle host: %v -> %v", before, got)
	}
}

func TestCoveredTimeNeedsTheUsersPolicyEnabled(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	h.pass()
	h.accrueTick()
	if got := h.covered(1001); got != time.Minute {
		t.Fatalf("covered = %v, want one minute while the policy is enabled", got)
	}
	// The policy is in load error: it covers nobody.
	h.tg.mu.Lock()
	for name, p := range h.tg.policies {
		if f, _ := FamilyOfName(name); f == FamilyControls {
			p.State = StateLoadError
			p.Error = "injected"
		}
	}
	h.tg.mu.Unlock()
	controls, _ := h.tg.find(FamilyControls)
	h.ctl.retryAt[controls.Name] = h.now.Add(time.Hour) // a repair was just tried
	h.pass()
	h.ctl.accrue()
	h.ctl.accrue()
	if got := h.covered(1001); got != time.Minute {
		t.Fatalf("covered = %v; a policy in load error covers nobody", got)
	}
	if !h.has(WarnPolicyLoadError) {
		t.Fatalf("warnings = %v", h.status().Warnings)
	}
}

func TestHitsKeepAUserInMonitor(t *testing.T) {
	h := newHarness(t, enforceIntent(Digest()), baseTargets)
	h.procs = twoUserProcs()
	h.burnedIn(1001, 24*time.Hour)
	h.pass()
	state := h.status()
	controlsName, burninName := mustName(t, state, FamilyControls), mustName(t, state, FamilyBurnin)

	// Bob (in controls-burnin) would have been denied: window restarts.
	h.burnedIn(1002, 23*time.Hour)
	h.ctl.RecordHit(Hit{Policy: burninName, UID: 1002, Path: "/home/bob/.ssh/id_rsa", Binary: "/usr/bin/cat"})
	h.ctl.RecordHit(Hit{Policy: burninName, UID: 1002, Path: "/home/bob/.ssh/id_rsa", Binary: "/usr/bin/cat"})
	h.ctl.RecordHit(Hit{Policy: burninName, UID: 1002, Path: "/home/bob/.bashrc", Binary: "/usr/bin/sh"})
	if got := h.covered(1002); got != 0 {
		t.Fatalf("covered = %v after a hit; the clean window must restart", got)
	}
	record := h.status().BurnIn.UIDs["1002"]
	ssh, persist := record.WouldBlock["kernel.ssh_private_key_read"], record.WouldBlock["kernel.persistence_write"]
	if ssh == nil || ssh.Count != 2 || ssh.Paths[0].Value != "/home/bob/.ssh/id_rsa" || ssh.Binaries[0].Value != "/usr/bin/cat" {
		t.Fatalf("ssh hits = %+v", ssh)
	}
	if persist == nil || persist.Count != 1 {
		t.Fatalf("persistence hits = %+v", persist)
	}
	// A user with hits is not ready even with more covered time than the window needs
	// until the window is clean again for the whole burn-in.
	h.ctl.tallyMu.Lock()
	ready := h.ctl.burn.Ready(1002, 24*time.Hour)
	h.ctl.tallyMu.Unlock()
	if ready {
		t.Fatal("a user that just hit a control is ready")
	}
	h.pass()
	if u := uidStatus(h.status(), 1002); u.State != UIDBurnIn || u.WouldBlock != 3 {
		t.Fatalf("bob = %+v", u)
	}

	// Alice's enforcing policy denies: that is the control working, not a reason to demote.
	h.ctl.RecordHit(Hit{Policy: controlsName, UID: 1001, Path: "/home/alice/.ssh/id_rsa", Binary: "/usr/bin/cat"})
	if got := h.covered(1001); got != 24*time.Hour {
		t.Fatalf("covered = %v; a denied open must not demote an enforcing user", got)
	}
	alice := h.status().BurnIn.UIDs["1001"]
	if alice.Blocked["kernel.ssh_private_key_read"] == nil || len(alice.WouldBlock) != 0 {
		t.Fatalf("alice = %+v", alice)
	}

	// Events from names the helper did not load are ignored.
	h.ctl.RecordHit(Hit{Policy: "defenseclaw-controls-deadbeef", UID: 1001, Path: "/home/alice/.ssh/id_rsa"})
	h.ctl.RecordHit(Hit{Policy: "someone-elses", UID: 1001, Path: "/home/alice/.ssh/id_rsa"})
	h.ctl.RecordHit(Hit{Policy: controlsName, UID: 4242, Path: "/home/alice/.ssh/id_rsa"}) // not enrolled
	if h.status().BurnIn.UIDs["1001"].Blocked["kernel.ssh_private_key_read"].Count != 1 {
		t.Fatal("a foreign event was counted")
	}
}

func uidStatus(state State, uid int) UIDStatus {
	for _, u := range state.UIDs {
		if u.UID == uid {
			return u
		}
	}
	return UIDStatus{}
}

func TestBurnInResetRules(t *testing.T) {
	dirs := Dirs{State: t.TempDir(), Run: t.TempDir()}
	now := time.Now()
	e1 := mustEnrollment(t, baseTargets)
	b := LoadBurnin(dirs)
	if resets := b.Sync("sha256:aaaaaaaaaaaa", e1, now); len(resets) != 0 {
		t.Fatalf("first sync reset %v", resets)
	}
	b.Accrue(1001, 30*time.Hour)
	b.Accrue(1002, 10*time.Hour)
	if !b.Ready(1001, 24*time.Hour) || b.Ready(1002, 24*time.Hour) {
		t.Fatal("readiness")
	}
	if !b.Ready(1002, 0) {
		t.Fatal("burn_in 0 skips the wait for an enrolled user")
	}
	if b.Ready(4242, 0) {
		t.Fatal("a user that is not enrolled is never ready")
	}
	if err := b.Save(dirs); err != nil {
		t.Fatal(err)
	}

	// Same digest, same enrollment: nothing is lost across a restart.
	again := LoadBurnin(dirs)
	again.Sync("sha256:aaaaaaaaaaaa", e1, now)
	if !again.Ready(1001, 24*time.Hour) {
		t.Fatal("evidence lost across a restart")
	}

	// A user who gains a connector starts over; the other keeps hers.
	e2 := mustEnrollment(t, baseTargets+`- user: bob
  uid: 1002
  user_home: /home/bob
  connector: amp
`)
	resets := again.Sync("sha256:aaaaaaaaaaaa", e2, now)
	if resets[1002] != "connector_set_changed" || len(resets) != 1 {
		t.Fatalf("resets = %v", resets)
	}
	if !again.Ready(1001, 24*time.Hour) || again.Covered(1002) != 0 {
		t.Fatal("only the user whose connector set changed starts over")
	}

	// A different control set voids everyone.
	resets = again.Sync("sha256:bbbbbbbbbbbb", e2, now)
	if resets[1001] != "kernel_policy_changed" || resets[1002] != "kernel_policy_changed" {
		t.Fatalf("resets = %v", resets)
	}
	if again.Ready(1001, 24*time.Hour) || again.Covered(1001) != 0 {
		t.Fatal("evidence measured against another control set must not carry over")
	}

	// A user who leaves the enrollment is forgotten.
	again.Accrue(1001, time.Hour)
	again.Sync("sha256:bbbbbbbbbbbb", mustEnrollment(t, "targets: []\n"), now)
	if len(again.Snapshot().UIDs) != 0 {
		t.Fatalf("records = %v", again.Snapshot().UIDs)
	}
}

func TestBumpKeepsTheMostFrequent(t *testing.T) {
	var list []Counted
	for i := 0; i < 20; i++ {
		list = bump(list, "/p/"+string(rune('a'+i)))
	}
	for i := 0; i < 5; i++ {
		list = bump(list, "/p/frequent")
	}
	if len(list) > maxCounted || list[0].Value != "/p/frequent" || list[0].Count < 5 {
		t.Fatalf("list = %+v", list)
	}
}
