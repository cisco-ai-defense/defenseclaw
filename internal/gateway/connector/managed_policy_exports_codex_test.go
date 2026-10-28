// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// GAP-0008/GAP-0101: managed Codex requirements on Linux and macOS bound
// every command to codex-hooks-v4 but registered the older ten-event matrix,
// without compact at SessionStart and without SessionEnd.
func TestManagedCodexUnversionedMatrixMatchesTheBoundContract(t *testing.T) {
	contract := ResolveHookContract("codex", "").Contract
	for _, goos := range []string{"linux", "darwin"} {
		groups, err := ManagedHookGroupsForOS("codex", "", goos)
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != len(contract.Events) {
			t.Fatalf("%s: %d groups, contract %s has %d events", goos, len(groups), contract.ContractID, len(contract.Events))
		}
		byEvent := map[string]ManagedHookGroup{}
		for i, group := range groups {
			if group.Event != contract.Events[i] {
				t.Fatalf("%s: group %d is %s, contract event is %s", goos, i, group.Event, contract.Events[i])
			}
			byEvent[group.Event] = group
		}
		if byEvent["SessionStart"].Matcher != "startup|resume|clear|compact" {
			t.Fatalf("%s: SessionStart matcher = %q", goos, byEvent["SessionStart"].Matcher)
		}
		if end, ok := byEvent["SessionEnd"]; !ok || end.Timeout != codexSessionEndHookGroup.timeout {
			t.Fatalf("%s: SessionEnd = %+v (registered %v)", goos, end, ok)
		}
	}

	// Windows keeps the ten events its machine-requirements installer
	// verifies, and registers the compact SessionStart source too.
	windows, err := ManagedHookGroupsForOS("codex", "", "windows")
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != len(codexHookGroups) {
		t.Fatalf("windows: %d groups, want %d", len(windows), len(codexHookGroups))
	}
	if windows[0].Event != "SessionStart" || windows[0].Matcher != "startup|resume|clear|compact" {
		t.Fatalf("windows: SessionStart = %+v", windows[0])
	}
}

// W2B review: managed Windows Codex registered SessionStart without the
// compact source, so a compact-source SessionStart never ran the hook while
// every command bound the v4 contract. The installer writes, verifies and
// removes the compact group, replaces the older one on upgrade, and Secure
// Client keeps its matrix.
func TestWindowsCodexMachineRequirementsCoverCompactSessionStart(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	opts.HookContractID = ResolveHookContract("codex", "").Contract.ContractID
	sessionStart := func(raw []byte) []interface{} {
		t.Helper()
		cfg, err := parseWindowsCodexRequirements(raw)
		if err != nil {
			t.Fatal(err)
		}
		hooks, _ := cfg["hooks"].(map[string]interface{})
		groups, _ := hooks["SessionStart"].([]interface{})
		return groups
	}

	rendered, _, err := reconcileWindowsCodexRequirements(nil, opts, true)
	if err != nil {
		t.Fatal(err)
	}
	groups := sessionStart(rendered)
	if len(groups) != 1 || groups[0].(map[string]interface{})["matcher"] != "startup|resume|clear|compact" {
		t.Fatalf("SessionStart groups = %v", groups)
	}
	if err := verifyWindowsCodexRequirementsBytes(rendered, opts); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// An install from before the compact matcher: verify refuses it and
	// reconcile replaces its group instead of adding a second one.
	legacy := windowsCodexMachineLayout(opts)
	legacy.groups = codexHookGroups
	cfg := map[string]interface{}{}
	if err := legacy.reconcile(cfg); err != nil {
		t.Fatal(err)
	}
	old, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsCodexRequirementsBytes(old, opts); err == nil {
		t.Fatal("verify accepted SessionStart without compact")
	}
	upgraded, changed, err := reconcileWindowsCodexRequirements(old, opts, true)
	if err != nil || !changed {
		t.Fatalf("upgrade: changed=%v err=%v", changed, err)
	}
	if groups := sessionStart(upgraded); len(groups) != 1 || groups[0].(map[string]interface{})["matcher"] != "startup|resume|clear|compact" {
		t.Fatalf("upgraded SessionStart groups = %v", groups)
	}

	// Removal takes the current group, and an older install's group that
	// the recorded preimage holds. With no such record, that group around
	// the current command is also what an administrator who cut compact
	// from the matcher wrote, so it stays (loop round 5 review).
	for _, tc := range []struct {
		name           string
		file, baseline []byte
		want           int
	}{
		{"current", rendered, nil, 0},
		{"legacy recorded as its own preimage", old, old, 0},
		{"legacy with no record of it", old, nil, 1},
	} {
		cleaned, _, err := removeWindowsCodexRequirementsOwnedChanges(tc.file, tc.baseline, opts)
		if err != nil {
			t.Fatal(err)
		}
		if groups := sessionStart(cleaned); len(groups) != tc.want {
			t.Fatalf("%s: SessionStart groups left after removal = %v, want %d", tc.name, groups, tc.want)
		}
	}

	secureClient := opts
	secureClient.SecureClient = true
	if groups := windowsCodexMachineLayout(secureClient).groups; groups[0].matcher != "startup|resume|clear" {
		t.Fatalf("Secure Client SessionStart matcher = %q", groups[0].matcher)
	}
}
