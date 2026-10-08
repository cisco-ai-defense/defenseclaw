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

package enterpriseunix

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

// The two limits of enforcement from the security review are stated where an
// administrator reads who is denied: a user whose agent is matched only by a
// process id, and every user but the lowest uid when several have a native
// agent install, stay in monitor.

func TestEnforceNeverCountsAUserWithoutADenyAnchor(t *testing.T) {
	in := readyInputs("enforce")
	done := int64(168 * 3600)
	in.State.UIDs = []kernelpolicy.UIDStatus{
		{UID: 1001, User: "dcr-std1", Connectors: []string{"claudecode"}, State: kernelpolicy.UIDEnforcing,
			CoveredSeconds: done, NeededSeconds: done},
		{UID: 1002, User: "dcr-std2", Connectors: []string{"claudecode"}, State: kernelpolicy.UIDMonitor,
			Reason: kernelpolicy.WarnBinaryScopeLimited, CoveredSeconds: done, NeededSeconds: done},
		{UID: 1003, User: "dcr-std3", Connectors: []string{"claudecode"}, State: kernelpolicy.UIDMonitor,
			Reason: kernelpolicy.WarnPIDMonitorOnly, CoveredSeconds: done, NeededSeconds: done},
	}
	users := readinessUsers(in, readinessNow)
	for _, user := range users[1:] {
		if user.Ready || user.Reason == "" {
			t.Fatalf("a user without a deny anchor is not enforced: %+v", user)
		}
	}
	want := "1 of 3 users is enforced; 2 stay in monitor without a deny anchor (" +
		kernelpolicy.WarnBinaryScopeLimited + ", " + kernelpolicy.WarnPIDMonitorOnly + ")."
	if got := enforceCounts(users, false); got != want {
		t.Fatalf("counts:\n%s\nwant:\n%s", got, want)
	}
	for _, user := range in.State.UIDs[1:] {
		state, why := userStateWords(TetragonUser{UID: user.UID, State: user.State, Reason: user.Reason}, burnInProgress{Ready: true})
		if state != "monitor only" || why == "" || why == user.Reason {
			t.Fatalf("%s reads %q (%q)", user.Reason, state, why)
		}
	}
}

// GAP-0055: running enforce, a user who finished burn-in counts as enforced
// only while the helper says it denies for them; one held in monitor by an
// operator's change or a pause is named with why.
func TestEnforceCountsOnlyUsersTheHelperEnforces(t *testing.T) {
	users := []TetragonUserReadiness{
		{UID: 1001, Ready: true, State: kernelpolicy.UIDMonitor, Reason: kernelpolicy.WarnOperatorOverride},
		{UID: 1002, Ready: true, State: kernelpolicy.UIDEnforcing},
		{UID: 1003, State: kernelpolicy.UIDBurnIn},
	}
	want := "1 of 3 users is enforced; 1 finished burn-in and is not enforced now (an operator changed the controls policy in Tetragon);" +
		" 1 stays in monitor until its burn-in completes."
	if got := enforceCounts(users, false); got != want {
		t.Fatalf("counts:\n%s\nwant:\n%s", got, want)
	}
	// Ready for enforce (from observe) still counts who would be enforced.
	if got := enforceCounts(users, true); !strings.HasPrefix(got, "2 of 3 users finished burn-in") {
		t.Fatalf("would: %s", got)
	}
}

// GAP-0056: the fleet summary counted a user without an agent and one held by
// the one-deny-anchor rule as "in burn-in", and an enforcing user with
// burn_in 0 read "reset". Each user now carries the phase the summary
// counts by.
func TestReadinessUsersCarryTheirFleetPhase(t *testing.T) {
	stubTetragonAccounts(t)
	in := readyInputs("enforce")
	in.Intent.BurnIn = "0"
	hit := readinessNow.Add(-time.Hour)
	in.State.UIDs = []kernelpolicy.UIDStatus{
		{UID: 1001, User: "dcr-std1", Connectors: []string{"claudecode"}, State: kernelpolicy.UIDEnforcing},
		{UID: 1002, User: "dcr-std2", Connectors: []string{"claudecode"}, State: kernelpolicy.UIDMonitor, Reason: kernelpolicy.WarnBinaryScopeLimited},
		{UID: 1003, User: "dcr-std3", Connectors: []string{"claudecode"}, State: kernelpolicy.UIDInactive, Reason: kernelpolicy.ReasonNoAnchors},
	}
	in.State.BurnIn.UIDs = map[string]*kernelpolicy.UIDRecord{"1001": {WindowStart: hit.Add(-time.Minute), WouldBlock: map[string]*kernelpolicy.HitStats{
		"kernel.ssh_private_key_read": {Count: 1, First: hit, Last: hit}}}}
	users := readinessUsers(in, readinessNow)
	want := []string{phaseEnforcing, phaseHeld, phaseNoAgent}
	for i, user := range users {
		if user.Phase != want[i] {
			t.Errorf("%s phase %q, want %q (%+v)", user.User, user.Phase, want[i], user)
		}
	}
	if users[0].Reset {
		t.Errorf("an enforcing user with burn_in 0 reads reset: %+v", users[0])
	}
	// In observe the users accrue burn-in; a ready one is ready, not held.
	for name, tc := range map[string]struct {
		user TetragonUserReadiness
		want string
	}{
		"observe burn-in": {TetragonUserReadiness{State: kernelpolicy.UIDMonitor, Reason: "observe mode"}, phaseBurnIn},
		"observe ready":   {TetragonUserReadiness{State: kernelpolicy.UIDMonitor, Reason: "observe mode", Ready: true}, phaseReady},
		"observe reset":   {TetragonUserReadiness{State: kernelpolicy.UIDMonitor, Reason: "observe mode", Reset: true}, phaseReset},
		"monitor only":    {TetragonUserReadiness{State: kernelpolicy.UIDMonitor, MonitorOnly: true}, phaseMonitorOnly},
	} {
		if got := userPhase(tc.user, false); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
	if got := userPhase(TetragonUserReadiness{State: kernelpolicy.UIDMonitor, Reason: kernelpolicy.WarnEnforcePaused, Ready: true}, true); got != phaseHeld {
		t.Errorf("a paused ready user in enforce: %q, want held", got)
	}
}

func TestReadyForEnforceSaysOneOfSeveralReadyUsersIsDenied(t *testing.T) {
	users := []TetragonUserReadiness{
		{UID: 1001, Ready: true}, {UID: 1002, Ready: true}, {UID: 1003},
	}
	got := enforceCounts(users, true)
	if !strings.HasPrefix(got, "2 of 3 users finished burn-in, and enforce denies for one of them") ||
		!strings.Contains(got, kernelpolicy.WarnBinaryScopeLimited) || !strings.Contains(got, "1 stays in monitor until its burn-in completes") {
		t.Fatalf("counts: %s", got)
	}
	if got := enforceCounts([]TetragonUserReadiness{{UID: 1001, Ready: true}, {UID: 1002, Ready: true}}, true); strings.HasPrefix(got, "every enrolled user") {
		t.Fatalf("two ready users are never both enforced: %s", got)
	}
	if got := enforceCounts([]TetragonUserReadiness{{UID: 1001, Ready: true}}, true); got != "every enrolled user (1) would be enforced now." {
		t.Fatalf("one ready user: %s", got)
	}
}

func TestEnforcementLimitCodesExplainTheLimit(t *testing.T) {
	for _, code := range []string{kernelpolicy.WarnPIDMonitorOnly, kernelpolicy.WarnBinaryScopeLimited} {
		got := tetragonMessage(code, tetragonFacts{})
		if strings.Contains(got, "reported by the sensor helper") || !strings.Contains(got, "Tetragon guide lists this limit") {
			t.Fatalf("%s: %s", code, got)
		}
	}
}
