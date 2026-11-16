// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// GAP-0907: a normal standalone uninstall refused an unchanged requirements
// file an earlier release wrote: its DefenseClaw groups carry that release's
// hook contract, so the removal's exact match (the current contract) kept
// them, the managed directory stayed with them, and the surviving reference
// stopped the uninstall with "explicit ownership transfer is required". The
// same held for a recorded preimage that already held such groups, and for a
// preimage that held only DefenseClaw's managed directory. A standalone
// removal now takes DefenseClaw's groups of any release and, with no hook
// left, its own managed directory; the administrator's hooks and settings
// stay, and an administrator hook next to the directory still keeps the
// removal unsafe.
func TestRemoveWindowsCodexRequirementsTakesTheGroupsOfAnEarlierRelease(t *testing.T) {
	earlier := testWindowsCodexMachineOptions()
	contracts := KnownHookContracts("codex")
	earlier.HookContractID = contracts[0].ContractID
	current := testWindowsCodexMachineOptions()
	current.HookContractID = contracts[len(contracts)-1].ContractID
	if earlier.HookContractID == current.HookContractID {
		t.Fatal("the test needs two hook contracts")
	}
	admin := []byte("approval_policy_floor = \"on-request\"\n")
	adminWithHook := []byte("approval_policy_floor = \"on-request\"\n\n[[hooks.PreToolUse]]\nmatcher = \"*\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = 'C:\\Tools\\audit.exe'\ntimeout = 5\n")
	written, _, err := reconcileWindowsCodexRequirements(admin, earlier, true)
	if err != nil {
		t.Fatal(err)
	}
	writtenWithHook, _, err := reconcileWindowsCodexRequirements(adminWithHook, earlier, true)
	if err != nil {
		t.Fatal(err)
	}
	onlyDir := []byte("approval_policy_floor = \"on-request\"\n\n[hooks]\nwindows_managed_dir = 'C:\\Program Files\\DefenseClaw\\bin'\n")
	for _, tc := range []struct {
		name               string
		file, baseline     []byte
		wantAdminHook      bool
		wantRefs           bool // an administrator hook keeps the directory
		wantLeftoversAfter bool
	}{
		{name: "the earlier release's file over the administrator's preimage", file: written, baseline: admin},
		{name: "the earlier release's file recorded as its own preimage", file: written, baseline: written},
		{name: "only the managed directory, recorded in the preimage", file: onlyDir, baseline: onlyDir},
		{name: "an administrator hook next to the earlier groups", file: writtenWithHook, baseline: adminWithHook, wantAdminHook: true, wantRefs: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if leftovers, err := windowsCodexRequirementsHoldOwnedLeftovers(tc.file, current); err != nil || !leftovers {
				t.Fatalf("leftovers before removal = %t, %v; want DefenseClaw's content recognized", leftovers, err)
			}
			cleaned, _, err := removeWindowsCodexRequirementsOwnedChanges(tc.file, tc.baseline, current)
			if err != nil {
				t.Fatal(err)
			}
			text := string(cleaned)
			if !strings.Contains(text, "approval_policy_floor") {
				t.Fatalf("the administrator's setting was dropped:\n%s", text)
			}
			// The 1.0.4 bridge and the direct cmd.exe form (GAP-1908).
			if strings.Contains(text, "EncodedCommand") || strings.Contains(text, " /d /v:off /c ") {
				t.Fatalf("a DefenseClaw group survived the removal:\n%s", text)
			}
			if got := strings.Contains(text, `C:\Tools\audit.exe`); got != tc.wantAdminHook {
				t.Fatalf("administrator hook kept = %t, want %t:\n%s", got, tc.wantAdminHook, text)
			}
			references, err := windowsCodexOwnedPathReferenceCount(cleaned, current)
			if err != nil {
				t.Fatal(err)
			}
			if (references != 0) != tc.wantRefs {
				t.Fatalf("surviving references = %d, want unsafe=%t:\n%s", references, tc.wantRefs, text)
			}
			if !tc.wantRefs {
				if leftovers, err := windowsCodexRequirementsHoldOwnedLeftovers(cleaned, current); err != nil || leftovers {
					t.Fatalf("leftovers after removal = %t, %v:\n%s", leftovers, err, text)
				}
			}
		})
	}
	// Secure Client keeps its exact-group removal: no contract, no change.
	secure := testWindowsCodexMachineOptions()
	secure.SecureClient = true
	if leftovers, err := windowsCodexRequirementsHoldOwnedLeftovers(written, secure); err != nil || leftovers {
		t.Fatalf("Secure Client leftovers = %t, %v", leftovers, err)
	}
	if leftovers, _ := windowsCodexRequirementsHoldOwnedLeftovers(admin, current); leftovers {
		t.Fatal("an administrator file with no DefenseClaw content holds leftovers")
	}
}
