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
	"strings"
	"testing"
	"time"
)

// The host's own Tetragon policies (item 1): DefenseClaw reads their events
// and never adds, changes or deletes one.

// customerPolicies are a customer's policies as the fake serves them: two
// from tetragon.tp.d (they come back when Tetragon restarts), one of them
// named in DefenseClaw's pattern, and one added over the API.
var customerPolicies = []string{"defenseclaw-controls-deadbeef", "10-file-sensitive", "20-net-connect"}

var tpdPolicies = []string{"defenseclaw-controls-deadbeef", "10-file-sensitive"}

const tpdPolicy = "10-file-sensitive"

func isCustomer(name string) bool {
	for _, customer := range customerPolicies {
		if name == customer {
			return true
		}
	}
	return false
}

// mutations returns the add, delete and configure calls of a call list.
func mutations(calls []string) []string {
	var out []string
	for _, call := range calls {
		for _, prefix := range []string{"add:", "delete:", "configure:"} {
			if strings.HasPrefix(call, prefix) {
				out = append(out, call)
			}
		}
	}
	return out
}

// TestCustomerPoliciesAreNeverManaged pins the never-mutate guarantee across
// every mode, a mode change, a pause, a Tetragon restart, an operator's own
// change to a customer policy, the off retire and the one-shot cleanup that
// uninstall, purge and rollback run: no add, delete or configure call names
// a customer policy, and each is still loaded, in its own mode, at the end.
func TestCustomerPoliciesAreNeverManaged(t *testing.T) {
	h := newHarness(t, Intent{Mode: ModeConsume}, baseTargets)
	h.procs = twoUserProcs()
	for _, name := range customerPolicies {
		h.tg.addForeign(name)
	}
	var calls []string
	step := func(what string, run func()) {
		t.Helper()
		run()
		taken := h.tg.take()
		for _, call := range mutations(taken) {
			name := strings.SplitN(strings.SplitN(call, ":", 2)[1], ":", 2)[0]
			if isCustomer(name) {
				t.Fatalf("%s: %s names a customer policy (calls %v)", what, call, taken)
			}
		}
		calls = append(calls, taken...)
	}
	step("observe", func() { h.start(observeIntent()); h.pass(); h.pass() })
	if h.ctl.Owns("defenseclaw-controls-deadbeef") || h.ctl.Owns(tpdPolicy) {
		t.Fatal("a customer policy is owned")
	}
	for _, name := range h.loadedFile() {
		if !h.ctl.Owns(name) {
			t.Fatalf("recorded %s is not owned", name)
		}
	}
	step("enforce", func() {
		h.start(enforceIntent(Digest()))
		h.pass()
		h.burnedIn(1001, 24*time.Hour)
		h.burnedIn(1002, 24*time.Hour)
		h.pass()
	})
	if p, ok := h.tg.find(FamilyControls); !ok || !p.Mode.Enforcing() {
		t.Fatalf("controls not enforcing: %+v", p)
	}
	step("pause and resume", func() { h.pause(time.Hour); h.pass(); h.resume(); h.pass() })
	step("an operator changes a customer policy", func() { h.tg.setMode("20-net-connect", LoadedMonitor); h.pass() })
	step("Tetragon restarts", func() {
		h.tg.restart()
		for _, name := range tpdPolicies {
			h.tg.addForeign(name) // tetragon.tp.d reloads; the API-added ones are gone
		}
		h.pass()
	})
	step("mode change to observe", func() { h.start(observeIntent()); h.pass() })
	step("off retires DefenseClaw's own", func() {
		h.start(Intent{Mode: ModeOff})
		if err := h.ctl.retireOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	step("observe again, then the one-shot cleanup", func() {
		h.start(observeIntent())
		h.pass()
		if _, err := Cleanup(context.Background(), h.tg, h.dirs); err != nil {
			t.Fatal(err)
		}
	})
	if got := strings.Join(h.tg.names(), ","); got != "10-file-sensitive,defenseclaw-controls-deadbeef" {
		t.Fatalf("left loaded %s; want the customer's policies only (20-net-connect left with Tetragon's restart)", got)
	}
	if len(mutations(calls)) == 0 {
		t.Fatal("the walk made no call of DefenseClaw's own; the pin tests nothing")
	}
}

func customerSourceOf(policies []CustomerPolicy, events CustomerEvents) CustomerSource {
	return func(time.Time) ([]CustomerPolicy, CustomerEvents) { return policies, events }
}

// TestCustomerSummaryIsPublishedWithItsWarnings: the state file carries the
// customer policies and their totals, a policy over its budget raises the
// capped warning for as long as it is in the last hour, and in consume (no
// pass lists Tetragon) a customer policy named in DefenseClaw's pattern
// raises the foreign-name warning.
func TestCustomerSummaryIsPublishedWithItsWarnings(t *testing.T) {
	h := newHarness(t, Intent{Mode: ModeConsume}, baseTargets)
	capped := []CustomerPolicy{
		{Name: "10-file-sensitive", Listed: true, Mode: "enforce", State: "enabled", Sensors: []string{"generic_lsm"},
			Actions: map[string]int64{"post": 9}, CustomerEvents: CustomerEvents{Seen: 12, Forwarded: 6, Dropped: 3, Capped: 3, CappedLastHour: 3, Container: 3}},
		{Name: "defenseclaw-controls-deadbeef", Listed: true, Mode: "monitor", State: "enabled"},
	}
	h.ctl.cfg.Customer = customerSourceOf(capped, CustomerEvents{Seen: 12, Forwarded: 6, Dropped: 3, Container: 3, Capped: 3, CappedLastHour: 3})
	h.ctl.persist()
	state, err := ReadState(h.dirs)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.CustomerPolicies) != 2 || state.CustomerPolicies[0].Seen != 12 || state.CustomerPolicies[0].Actions["post"] != 9 ||
		state.CustomerEvents == nil || state.CustomerEvents.Forwarded != 6 {
		t.Fatalf("customer state %+v %+v", state.CustomerPolicies, state.CustomerEvents)
	}
	if !h.has(WarnCustomerEventsCapped+":10-file-sensitive") || !h.has(WarnForeignName+":defenseclaw-controls-deadbeef") {
		t.Fatalf("warnings %v", h.status().Warnings)
	}
	// The hour passed and the shaped policy was removed: both warnings go.
	h.ctl.cfg.Customer = customerSourceOf([]CustomerPolicy{{Name: "10-file-sensitive", Listed: true}}, CustomerEvents{Seen: 12})
	h.ctl.persist()
	for _, warning := range h.status().Warnings {
		if strings.HasPrefix(warning, WarnCustomerEventsCapped) || strings.HasPrefix(warning, WarnForeignName) {
			t.Fatalf("stale warning %s", warning)
		}
	}

	// In observe the pass lists Tetragon itself: the capped warning still
	// comes from the customer source, the foreign one from the listing.
	h = newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	h.tg.addForeign("defenseclaw-controls-deadbeef")
	h.ctl.cfg.Customer = customerSourceOf(capped, CustomerEvents{})
	h.pass()
	if !h.has(WarnCustomerEventsCapped+":10-file-sensitive") || !h.has(WarnForeignName+":defenseclaw-controls-deadbeef") {
		t.Fatalf("observe warnings %v", h.status().Warnings)
	}
}

// TestConsumeWritesTheCustomerSummaryOnItsCadence: consume has no pass, so
// the state is written every Flush interval for the customer counts.
func TestConsumeWritesTheCustomerSummaryOnItsCadence(t *testing.T) {
	h := newHarness(t, Intent{Mode: ModeConsume}, baseTargets)
	seen := int64(0)
	h.ctl.cfg.Customer = func(time.Time) ([]CustomerPolicy, CustomerEvents) {
		seen++
		return []CustomerPolicy{{Name: "10-file-sensitive", Listed: true, CustomerEvents: CustomerEvents{Seen: seen}}}, CustomerEvents{Seen: seen}
	}
	h.ctl.cfg.Intervals.Flush = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = h.ctl.Run(ctx) }()
	waitUntil(t, "the customer counts to be written twice", func() bool {
		state, err := ReadState(h.dirs)
		return err == nil && state.CustomerEvents != nil && state.CustomerEvents.Seen >= 3
	})
	cancel()
	<-done
}

// TestOwnsIsTheRecord: a recorded name is DefenseClaw's for as long as it is
// recorded and for a short grace after it is retired; a name in DefenseClaw's
// pattern that this helper never loaded, or only compiled, never is.
func TestOwnsIsTheRecord(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	h.tg.addForeign("defenseclaw-observe-deadbeef")
	h.pass()
	recorded := h.loadedFile()
	if len(recorded) == 0 {
		t.Fatal("nothing recorded")
	}
	for _, name := range recorded {
		if !h.ctl.Owns(name) {
			t.Fatalf("%s is recorded", name)
		}
	}
	if h.ctl.Owns("defenseclaw-observe-deadbeef") || h.ctl.Owns("customer-policy") {
		t.Fatal("an unrecorded name is owned")
	}
	h.ctl.setIndex("defenseclaw-controls-0badc0de", PathIndex{})
	if h.ctl.Owns("defenseclaw-controls-0badc0de") {
		t.Fatal("a compiled, unloaded name is owned")
	}
	// Retired by off: still owned for the grace, so its last events are
	// DefenseClaw's, then not.
	h.start(Intent{Mode: ModeOff})
	if err := h.ctl.retireOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.ctl.syncTally()
	if !h.ctl.Owns(recorded[0]) {
		t.Fatalf("%s retired a moment ago", recorded[0])
	}
	h.now = h.now.Add(31 * time.Second)
	h.ctl.syncTally()
	if h.ctl.Owns(recorded[0]) {
		t.Fatalf("%s owned after the grace", recorded[0])
	}
}

// TestUIDProgressEverySixHours: a user not ready yet gets a uid_progress
// change with covered and needed seconds every six hours.
func TestUIDProgressEverySixHours(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	progress := func() []Change {
		var out []Change
		for _, change := range h.status().Changes {
			if change.Event == EventUIDProgress {
				out = append(out, change)
			}
		}
		return out
	}
	h.pass()
	first := progress()
	if len(first) != 2 || first[0].NeededSeconds != int64(24*time.Hour/time.Second) || first[0].UID == nil {
		t.Fatalf("progress %+v", first)
	}
	h.pass()
	if got := progress(); len(got) != 2 {
		t.Fatalf("a second pass emitted %d", len(got)-2)
	}
	h.burnedIn(1001, 24*time.Hour)
	h.now = h.now.Add(6 * time.Hour)
	h.pass()
	got := progress()
	if len(got) != 3 || *got[2].UID != 1002 {
		t.Fatalf("after six hours %+v", got)
	}
}

// TestHitTotalsCountEveryUser: the controls' events are totalled for every
// uid, one without a burn-in record included, so the gateway's per-cycle
// growth counts would-blocks nothing else attributes.
func TestHitTotalsCountEveryUser(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	h.pass()
	controls := mustName(t, h.status(), FamilyControls)
	h.ctl.RecordHit(Hit{Policy: controls, UID: 4242, Path: "/home/nobody/.ssh/id_rsa", At: h.now})
	h.ctl.RecordHit(Hit{Policy: controls, UID: 1001, Path: "/home/alice/.ssh/id_rsa", At: h.now})
	h.ctl.RecordHit(Hit{Policy: "defenseclaw-controls-deadbeef", UID: 1001, Path: "/home/alice/.ssh/id_rsa", At: h.now})
	if totals := h.status().HitTotals; totals["would_block_total"] != 2 || totals["blocked_total"] != 0 {
		t.Fatalf("totals %v", totals)
	}
}
