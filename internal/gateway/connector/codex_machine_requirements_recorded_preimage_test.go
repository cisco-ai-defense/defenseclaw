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
					if leftovers, err := windowsCodexRecordedRequirementsHoldOwnedLeftovers(candidate, current); err != nil || leftovers {
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

// The live leftover check keeps its meaning: this install's command in a
// shape it does not render, in a file DefenseClaw did not record, is an
// administrator's edit and not DefenseClaw's (TestWindowsCodexUninstall-
// KeepsAnAdministratorNarrowedSessionStart). Only the recorded preimage
// counts it as DefenseClaw's.
func TestWindowsCodexRecordedLeftoversDifferOnlyForTheEarlierShape(t *testing.T) {
	for _, contract := range KnownHookContracts("codex") {
		if !codexContractCertifiesCompactSessionStart(contract.ContractID) {
			continue
		}
		current := testWindowsCodexMachineOptions()
		current.HookContractID = contract.ContractID
		command := windowsCodexBoundManagedHookCommand(current.HookBinary, "SessionStart", contract.ContractID)
		var earlierMatcher string
		for _, group := range codexHookGroups {
			if group.eventType == "SessionStart" {
				earlierMatcher = group.matcher
			}
		}
		raw, err := toml.Marshal(map[string]interface{}{"hooks": map[string]interface{}{
			"SessionStart": []interface{}{windowsCodexTestGroup(earlierMatcher, windowsCodexMachineHandler(command, 30))},
		}})
		if err != nil {
			t.Fatal(err)
		}
		live, err := windowsCodexRequirementsHoldOwnedLeftovers(raw, current)
		if err != nil || live {
			t.Fatalf("%s: live leftovers = %t, %v", contract.ContractID, live, err)
		}
		recorded, err := windowsCodexRecordedRequirementsHoldOwnedLeftovers(raw, current)
		if err != nil || !recorded {
			t.Fatalf("%s: recorded leftovers = %t, %v", contract.ContractID, recorded, err)
		}
	}
}
