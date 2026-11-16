// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

// GAP-1456: a published 1.0.2 install adopted requirements that an earlier
// DefenseClaw had left behind (the managed directory and this install's
// SessionStart group in the 1.0.2 shape) and recorded them as its preimage.
// After the upgrade to this release the live file is DefenseClaw's exact
// publication, so the removal restores that preimage. It held DefenseClaw's
// group in a shape this release does not render, which the leftover check
// took for an administrator's edit: the preimage came back verbatim with
// windows_managed_dir still naming the install tree, and teardown prepare
// refused with one surviving reference. A group the record itself holds is
// DefenseClaw's, so the restored preimage is cleaned of it.
func TestWindowsCodexRemovalCleansTheRecordedPreimageOfAnEarlierShape(t *testing.T) {
	for _, contract := range KnownHookContracts("codex") {
		if !codexContractCertifiesCompactSessionStart(contract.ContractID) {
			continue
		}
		t.Run(contract.ContractID, func(t *testing.T) {
			current := testWindowsCodexMachineOptions()
			current.HookContractID = contract.ContractID
			command := windowsCodexBoundManagedHookCommand(current.HookBinary, "SessionStart", contract.ContractID)
			var earlierMatcher string
			for _, group := range codexHookGroups {
				if group.eventType == "SessionStart" {
					earlierMatcher = group.matcher
				}
			}
			if earlierMatcher == "" || earlierMatcher == codexCompactSessionStartMatcher {
				t.Fatalf("the earlier SessionStart matcher %q is not an earlier shape", earlierMatcher)
			}
			earlier := windowsCodexTestGroup(earlierMatcher, windowsCodexMachineHandler(command, 30))
			adminGroup := windowsCodexTestGroup("*", windowsCodexMachineHandler(`C:\Tools\audit.exe --codex`, 30))
			preimage := func(t *testing.T, groups map[string]interface{}, managedDir string) []byte {
				t.Helper()
				hooks := map[string]interface{}{}
				if managedDir != "" {
					hooks["windows_managed_dir"] = managedDir
				}
				for event, group := range groups {
					hooks[event] = []interface{}{group}
				}
				raw, err := toml.Marshal(map[string]interface{}{
					"allow_managed_hooks_only": true,
					"features":                 map[string]interface{}{"hooks": true},
					"hooks":                    hooks,
				})
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			for _, tc := range []struct {
				name        string
				preimage    []byte
				wantAdmin   bool
				wantManaged bool
			}{
				{"the earlier SessionStart group and the managed directory",
					preimage(t, map[string]interface{}{"SessionStart": earlier}, current.ManagedDir), false, false},
				{"the earlier SessionStart group alone",
					preimage(t, map[string]interface{}{"SessionStart": earlier}, ""), false, false},
				{"the earlier SessionStart group beside an administrator hook",
					preimage(t, map[string]interface{}{"SessionStart": earlier, "PreToolUse": adminGroup}, current.ManagedDir), true, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					published, _, err := reconcileWindowsCodexRequirements(tc.preimage, current, false)
					if err != nil {
						t.Fatal(err)
					}
					state := windowsCodexMachineOwnership{
						SchemaVersion:   windowsCodexMachineRequirementsSchema,
						PreimageExisted: true,
						Preimage:        tc.preimage,
						PreimageSHA256:  windowsCodexMachineHash(tc.preimage),
						PostimageSHA256: windowsCodexMachineHash(published),
					}
					candidate, exists, _, disposition, err := windowsCodexRemovalCandidate(published, true, state, current)
					if err != nil {
						t.Fatal(err)
					}
					if !exists || disposition != "restored_preimage" {
						t.Fatalf("removal = exists %t, %q", exists, disposition)
					}
					if strings.Contains(string(candidate), "defenseclaw-hook") ||
						windowsCodexTestCountGroup(t, candidate, "SessionStart", windowsCodexTestNormalized(t, earlier)) != 0 {
						t.Fatalf("a DefenseClaw group survived the removal:\n%s", candidate)
					}
					if leftovers, err := windowsCodexRequirementsHoldOwnedLeftovers(candidate, current); err != nil || leftovers {
						t.Fatalf("DefenseClaw content left = %t, %v:\n%s", leftovers, err, candidate)
					}
					references, err := windowsCodexOwnedPathReferenceCount(candidate, current)
					if err != nil {
						t.Fatal(err)
					}
					if tc.wantManaged {
						// An administrator hook keeps the shared managed
						// directory, which keeps the binary removal blocked
						// until an administrator rehomes it.
						if references == 0 {
							t.Fatalf("the managed directory of an administrator hook was dropped:\n%s", candidate)
						}
					} else if references != 0 {
						t.Fatalf("references = %d after removal:\n%s", references, candidate)
					}
					if got := windowsCodexTestCountGroup(t, candidate, "PreToolUse", windowsCodexTestNormalized(t, adminGroup)); (got == 1) != tc.wantAdmin {
						t.Fatalf("administrator hook copies = %d, want kept %t:\n%s", got, tc.wantAdmin, candidate)
					}
				})
			}
		})
	}
}

// GAP-0907: a standalone removal takes this install's command in the
// SessionStart shape of 1.0.2 and 1.0.3 from any file, not only from a
// recorded preimage. A live file that is not DefenseClaw's exact publication
// (a guardian or Codex rewrite, a recovered earlier release's bytes) over an
// administrator preimage that never held the group kept it as an
// administrator's edit: its windows_managed_dir stayed, teardown refused with
// "1 surviving Codex managed hook references ... explicit ownership transfer
// is required", and only /uninstall FORCE=1 finished. An administrator hook
// beside it still keeps the managed directory and the removal unsafe.
func TestWindowsCodexRemovalTakesTheEarlierSessionStartShapeFromALiveFile(t *testing.T) {
	for _, contract := range KnownHookContracts("codex") {
		if !codexContractCertifiesCompactSessionStart(contract.ContractID) {
			continue
		}
		t.Run(contract.ContractID, func(t *testing.T) {
			current := testWindowsCodexMachineOptions()
			current.HookContractID = contract.ContractID
			command := windowsCodexBoundManagedHookCommand(current.HookBinary, "SessionStart", contract.ContractID)
			var earlierMatcher string
			for _, group := range codexHookGroups {
				if group.eventType == "SessionStart" {
					earlierMatcher = group.matcher
				}
			}
			earlier := windowsCodexTestGroup(earlierMatcher, windowsCodexMachineHandler(command, 30))
			adminGroup := windowsCodexTestGroup("*", windowsCodexMachineHandler(`C:\Tools\audit.exe --codex`, 30))
			admin := []byte("approval_policy_floor = \"on-request\"\n")
			for _, tc := range []struct {
				name      string
				extra     map[string]interface{}
				wantAdmin bool
			}{
				{"the earlier group alone", nil, false},
				{"the earlier group beside an administrator hook", map[string]interface{}{"PreToolUse": []interface{}{adminGroup}}, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					published, _, err := reconcileWindowsCodexRequirements(admin, current, true)
					if err != nil {
						t.Fatal(err)
					}
					cfg, err := parseWindowsCodexRequirements(published)
					if err != nil {
						t.Fatal(err)
					}
					hooks := cfg["hooks"].(map[string]interface{})
					groups, _ := hooks["SessionStart"].([]interface{})
					hooks["SessionStart"] = append([]interface{}{earlier}, groups...)
					for event, value := range tc.extra {
						hooks[event] = value
					}
					live, err := toml.Marshal(cfg)
					if err != nil {
						t.Fatal(err)
					}
					state := windowsCodexMachineOwnership{
						SchemaVersion:   windowsCodexMachineRequirementsSchema,
						PreimageExisted: true,
						Preimage:        admin,
						PreimageSHA256:  windowsCodexMachineHash(admin),
						PostimageSHA256: windowsCodexMachineHash(published),
					}
					candidate, exists, _, disposition, err := windowsCodexRemovalCandidate(live, true, state, current)
					if err != nil {
						t.Fatal(err)
					}
					if !exists || disposition != "surgical_preservation" {
						t.Fatalf("removal = exists %t, %q", exists, disposition)
					}
					if windowsCodexTestCountGroup(t, candidate, "SessionStart", windowsCodexTestNormalized(t, earlier)) != 0 {
						t.Fatalf("the earlier DefenseClaw SessionStart group survived the removal:\n%s", candidate)
					}
					if leftovers, err := windowsCodexRequirementsHoldOwnedLeftovers(candidate, current); err != nil || leftovers {
						t.Fatalf("DefenseClaw content left = %t, %v:\n%s", leftovers, err, candidate)
					}
					references, err := windowsCodexOwnedPathReferenceCount(candidate, current)
					if err != nil {
						t.Fatal(err)
					}
					if tc.wantAdmin {
						if references == 0 || windowsCodexTestCountGroup(t, candidate, "PreToolUse", windowsCodexTestNormalized(t, adminGroup)) != 1 {
							t.Fatalf("the administrator hook or its managed directory was dropped (references %d):\n%s", references, candidate)
						}
					} else if references != 0 {
						t.Fatalf("references = %d after removal; the uninstall would refuse:\n%s", references, candidate)
					}
					if !strings.Contains(string(candidate), "approval_policy_floor") {
						t.Fatalf("the administrator setting was dropped:\n%s", candidate)
					}
				})
			}
		})
	}
}
