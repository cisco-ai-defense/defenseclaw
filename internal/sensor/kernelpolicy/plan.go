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
	"sort"
)

// User states in the rollout.
const (
	UIDEnforcing = "enforcing"
	UIDBurnIn    = "burn_in"
	UIDMonitor   = "monitor"
	UIDInactive  = "inactive"
)

// PlanInput is every input to the desired-state decision. All of it is
// root-owned or derived from root-owned inputs: the drop-in, the guardian
// manifest, the helper's own state and Tetragon itself.
type PlanInput struct {
	Intent     Intent
	Agent      Agent
	Paused     bool
	Overrides  map[Family]Override
	Enrollment Enrollment
	// Ready reports whether a user finished burn-in.
	Ready func(uid int) bool
}

// Plan is what should be loaded.
type Plan struct {
	Observe  bool
	Connect  bool
	Controls *Scope
	Burnin   *Scope
	// Effective is the mode that actually runs.
	Effective Mode
	UIDs      map[int]UIDStatus
	Warnings  []string
}

// MakePlan decides what runs. Every cap only narrows:
//
//   - observe and enforce need Tetragon 1.7.x and a known pid;
//   - enforce needs the administrator's approval of this build's control-set
//     digest, a Tetragon that will not keep sensors after it stops, a BPF LSM,
//     no pause, and a user that finished burn-in;
//   - a family an operator moved to monitor loads in monitor, and one an
//     operator deleted is not loaded, until the intent changes.
func MakePlan(in PlanInput) Plan {
	plan := Plan{Effective: in.Intent.Mode, UIDs: map[int]UIDStatus{}}
	if !in.Intent.Mode.LoadsPolicies() {
		return plan
	}
	plan.Effective = ModeObserve
	if in.Agent.PID <= 0 {
		plan.Warnings = append(plan.Warnings, ReasonIdentityUnknown)
		plan.Effective = ModeConsume
		return plan
	}
	if !in.Agent.supportsPolicies() {
		plan.Warnings = append(plan.Warnings, WarnUnsupportedVersion)
		plan.Effective = ModeConsume
		return plan
	}
	lsm := !in.Agent.LSMKnown || in.Agent.LSM
	if !lsm {
		plan.Warnings = append(plan.Warnings, WarnLSMUnavailable)
	}
	hasOverride := func(family Family, kind OverrideKind) bool {
		o, ok := in.Overrides[family]
		return ok && o.Kind == kind
	}
	for _, family := range Families {
		if _, ok := in.Overrides[family]; ok {
			plan.Warnings = append(plan.Warnings, WarnOperatorOverride+":"+string(family))
		}
	}
	plan.Observe = lsm && !hasOverride(FamilyObserve, OverrideDeleted)
	plan.Connect = !hasOverride(FamilyConnect, OverrideDeleted)

	uids := in.Enrollment.UIDs()
	status := func(uid int, state, reason string) {
		plan.UIDs[uid] = UIDStatus{UID: uid, User: in.Enrollment.UserOf(uid),
			Connectors: in.Enrollment.Connectors(uid), State: state, Reason: reason}
	}
	if len(uids) == 0 || !lsm {
		return plan
	}

	// Monitor scope: every enrolled connector is anchored, which is harmless
	// and lets an administrator measure before turning hooks to action.
	monitorAll := Scope{Mode: PolicyMonitor, UIDs: uids}
	controls := func(scope Scope) {
		if !hasOverride(FamilyControls, OverrideDeleted) {
			plan.Controls = &scope
		}
	}
	burnin := func(scope Scope) {
		if !hasOverride(FamilyBurnin, OverrideDeleted) {
			plan.Burnin = &scope
		}
	}

	if in.Intent.Mode == ModeObserve {
		controls(monitorAll)
		for _, uid := range uids {
			status(uid, UIDMonitor, "observe mode")
		}
		return plan
	}

	// mode: enforce.
	capped := ""
	switch {
	case len(in.Intent.EnforceAcks) == 0:
		capped = WarnEnforceAckMissing
	case !in.Intent.Approves():
		capped = WarnEnforceAckStale
	case !in.Agent.KeepSensorsOnExitKnown || in.Agent.KeepSensorsOnExit:
		capped = WarnPersistentSensors
	case in.Paused:
		capped = WarnEnforcePaused
	}
	if capped != "" {
		plan.Warnings = append(plan.Warnings, capped)
		controls(monitorAll)
		for _, uid := range uids {
			status(uid, UIDMonitor, capped)
		}
		return plan
	}
	if in.Intent.BurnIn == 0 {
		plan.Warnings = append(plan.Warnings, WarnBurnInSkipped)
	}

	enforceSet := map[string]bool{}
	for _, connector := range in.Intent.EnforceConnectors {
		if IsCLIConnector(connector) {
			enforceSet[connector] = true
		}
	}
	for _, connector := range enrolledConnectors(in.Enrollment) {
		if IsCLIConnector(connector) && !enforceSet[connector] {
			plan.Warnings = append(plan.Warnings, WarnGuardrailObserve+":"+connector)
		}
	}
	var ready, waiting []int
	for _, uid := range uids {
		hasAction := false
		for _, connector := range in.Enrollment.Connectors(uid) {
			if enforceSet[connector] {
				hasAction = true
			}
		}
		switch {
		case !hasAction:
			waiting = append(waiting, uid)
			status(uid, UIDInactive, ReasonGuardrailObserve)
		case in.Ready != nil && in.Ready(uid):
			ready = append(ready, uid)
			status(uid, UIDEnforcing, "")
		default:
			waiting = append(waiting, uid)
			status(uid, UIDBurnIn, "")
		}
	}
	if len(ready) == 0 {
		plan.Warnings = append(plan.Warnings, ReasonNoReadyUsers)
		controls(monitorAll)
		return plan
	}
	plan.Effective = ModeEnforce
	mode := PolicyEnforce
	if hasOverride(FamilyControls, OverrideMonitor) {
		mode = PolicyMonitor
		plan.Effective = ModeObserve
	}
	controls(Scope{Mode: mode, UIDs: ready, Connectors: enforceSet})
	if len(waiting) > 0 {
		burnin(Scope{Mode: PolicyMonitor, UIDs: waiting, Connectors: enforceSet})
	}
	return plan
}

func enrolledConnectors(e Enrollment) []string {
	seen := map[string]bool{}
	for _, row := range e.Rows {
		if row.Connector != "" {
			seen[row.Connector] = true
		}
	}
	out := sortedKeys(seen)
	sort.Strings(out)
	return out
}
