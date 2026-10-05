// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

func TestKiroWindowsManagedHookContract(t *testing.T) {
	for raw, want := range map[string]string{
		"2.24.1":                         KiroWindowsManagedCLIContractID,
		"2.30.0":                         KiroWindowsManagedCLIContractID,
		"2.20.0":                         "",
		"1.0.190" + KiroIDEVersionSuffix: KiroWindowsManagedIDEContractID,
		"1.0.170" + KiroIDEVersionSuffix: "",
		"1.0.190":                        "", // an IDE version without its suffix is kiro-cli's
	} {
		got := ResolveWindowsManagedKiroHookContract(raw)
		if got.Contract.ContractID != want || (want != "") != (got.Status == HookCompatibilityKnown) || got.RawVersion != raw {
			t.Fatalf("%s resolved to %q (%s, %s), want %q", raw, got.Contract.ContractID, got.Status, got.Reason, want)
		}
	}

	// The managed footprint pins the contract; the gateway serving it
	// resolves the pin without the managed flag. Per-user Kiro stays
	// not gated, and Windows managed IDs are not registered elsewhere.
	managed := resolveHookContractForOptions("kiro", SetupOpts{GOOS: "windows", ManagedEnterprise: true, AgentVersion: "2.24.1"})
	if managed.Contract.ContractID != KiroWindowsManagedCLIContractID {
		t.Fatalf("managed Windows Kiro = %q (%s)", managed.Contract.ContractID, managed.Reason)
	}
	gateway := resolveHookContractForOptions("kiro", SetupOpts{GOOS: "windows", AgentVersion: "2.24.1", HookContractID: KiroWindowsManagedCLIContractID})
	if gateway.Status != HookCompatibilityKnown || gateway.Contract.ContractID != KiroWindowsManagedCLIContractID {
		t.Fatalf("pinned Windows Kiro = %q (%s, %s)", gateway.Contract.ContractID, gateway.Status, gateway.Reason)
	}
	if perUser := resolveHookContractForOptions("kiro", SetupOpts{GOOS: "windows", AgentVersion: "2.24.1"}); perUser.Status != HookCompatibilityNotGated {
		t.Fatalf("per-user Windows Kiro = %s", perUser.Status)
	}
	if _, ok := hookContractByIDForOS("kiro", KiroWindowsManagedCLIContractID, "linux"); ok {
		t.Fatal("managed Windows Kiro contract resolved on Linux")
	}

	// The profile keeps the paths, scope and correlation it had unpinned.
	opts := SetupOpts{GOOS: "windows", ManagedEnterprise: true, AgentVersion: "2.24.1"}
	plain := HookProfile{Name: "kiro", Capabilities: HookCapability{Scope: "user", ConfigPath: "hooks.json"}}
	profile := ApplyHookContract(plain, opts)
	if profile.ContractID != KiroWindowsManagedCLIContractID || profile.Capabilities.Scope != "user" ||
		profile.Capabilities.ConfigPath != "hooks.json" || !profile.Capabilities.CanBlock ||
		profile.Correlation.ProfileVersion != CorrelationProfileExplicitV1 || profile.ResponseFieldName != "" {
		t.Fatalf("managed Windows Kiro profile = %+v", profile)
	}
}
