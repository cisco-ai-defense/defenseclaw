// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

func kiroLockEntryFor(t *testing.T, raw string) HookContractLockEntry {
	t.Helper()
	resolution := ResolveHookContract("kiro", raw)
	if resolution.Status != HookCompatibilityNotGated || resolution.Contract.ContractID != "" {
		t.Fatalf("kiro %q = %+v, want not-gated with no contract", raw, resolution)
	}
	return HookContractLockEntry{
		Connector:              "kiro",
		RawAgentVersion:        resolution.RawVersion,
		NormalizedAgentVersion: resolution.NormalizedVersion,
		CompatibilityStatus:    resolution.Status,
	}
}

// GAP-2427: a kiro-cli self-update (2.26.1 -> 2.35.1) after the lock stopped
// the gateway with hook contract drift and rolled the upgrade back. Kiro hooks
// are not version-gated, so the update is admitted and the lock refreshed; an
// update to a kiro-cli below the floor, an unread version and strict (Secure
// Client) resolution still drift and are refused.
func TestNotGatedAgentUpdateIsAdmittedAboveTheKiroFloor(t *testing.T) {
	previous := kiroLockEntryFor(t, "kiro-cli 2.26.1")
	current := kiroLockEntryFor(t, "kiro-cli 2.35.1")
	if !HookContractCompatibilityDrifted(previous, current) {
		t.Fatal("a kiro-cli version change must still be seen as drift")
	}
	if !HookContractAgentUpdateAdmitted(previous, current) {
		t.Fatal("kiro-cli 2.26.1 -> 2.35.1 must be admitted: kiro hooks are not version-gated")
	}
	ide := kiroLockEntryFor(t, "1.0.190"+KiroIDEVersionSuffix)
	if !HookContractAgentUpdateAdmitted(kiroLockEntryFor(t, "1.0.182"+KiroIDEVersionSuffix), ide) {
		t.Fatal("a Kiro IDE update must be admitted")
	}

	belowFloor := kiroLockEntryFor(t, "kiro-cli 2.26.5")
	if HookContractAgentUpdateAdmitted(previous, belowFloor) {
		t.Fatalf("an update to a kiro-cli below %s must not be admitted", KiroCLIHookFloor)
	}
	unread := current
	unread.RawAgentVersion, unread.NormalizedAgentVersion = "kiro-cli", ""
	if HookContractAgentUpdateAdmitted(previous, unread) {
		t.Fatal("an update to a version that could not be read must not be admitted")
	}
	withContract := current
	withContract.ContractID = "kiro-hooks-v1"
	if HookContractAgentUpdateAdmitted(previous, withContract) {
		t.Fatal("a not-gated entry that names a contract is not the not-gated shape")
	}
	if HookContractAgentUpdateAdmitted(previous, previous) {
		t.Fatal("an unchanged agent is not an update")
	}

	SetStrictHookContractResolution(true)
	t.Cleanup(func() { SetStrictHookContractResolution(false) })
	if HookContractAgentUpdateAdmitted(previous, current) {
		t.Fatal("strict resolution must refuse agent updates as before")
	}
}
