// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// Loop round 2 review (Windows consolidation): an administrator who cuts the
// compact source from this install's SessionStart matcher gets the group a
// release before the compact matcher rendered around the same command.
// Reconcile took it as that release's group, so every repair deleted it.
// Reconcile now replaces it only in a file nobody edited since DefenseClaw
// published it that holds no exact group of this install: an upgrade from
// 1.0.2 or 1.0.3. Every other copy stays next to the exact group, through
// repeated repairs. The uninstall that follows takes it with DefenseClaw's
// other groups: it runs the binary the uninstall deletes (GAP-0907).
func TestReconcileWindowsCodexKeepsAnAdministratorNarrowedSessionStart(t *testing.T) {
	for _, contract := range KnownHookContracts("codex") {
		if !codexContractCertifiesCompactSessionStart(contract.ContractID) {
			continue
		}
		t.Run(contract.ContractID, func(t *testing.T) {
			current := testWindowsCodexMachineOptions()
			current.HookContractID = contract.ContractID
			command := windowsCodexBoundManagedHookCommand(current.HookBinary, "SessionStart", contract.ContractID)
			compact := windowsCodexTestGroup(codexCompactSessionStartMatcher, windowsCodexMachineHandler(command, 30))
			var earlierMatcher string
			for _, group := range codexHookGroups {
				if group.eventType == "SessionStart" {
					earlierMatcher = group.matcher
				}
			}
			if earlierMatcher == "" || earlierMatcher == codexCompactSessionStartMatcher {
				t.Fatalf("the earlier SessionStart matcher %q is not an earlier shape", earlierMatcher)
			}
			narrowed := windowsCodexTestGroup(earlierMatcher, windowsCodexMachineHandler(command, 30))
			wantNarrowed := windowsCodexTestNormalized(t, narrowed)
			wantCompact := windowsCodexTestNormalized(t, compact)
			admin := []byte("approval_policy_floor = \"on-request\"\n")
			installed, _, err := reconcileWindowsCodexRequirements(admin, current, true)
			if err != nil {
				t.Fatal(err)
			}
			// edit is installed with SessionStart set to groups, plus an
			// unrelated administrator change when other is set.
			edit := func(t *testing.T, other bool, groups ...interface{}) []byte {
				t.Helper()
				cfg, err := parseWindowsCodexRequirements(installed)
				if err != nil {
					t.Fatal(err)
				}
				cfg["hooks"].(map[string]interface{})["SessionStart"] = groups
				if other {
					cfg["allowed_sandbox_modes"] = []interface{}{"read-only"}
				}
				raw, err := toml.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			counts := func(t *testing.T, raw []byte) (int, int) {
				t.Helper()
				return windowsCodexTestCountGroup(t, raw, "SessionStart", wantNarrowed), windowsCodexTestCountGroup(t, raw, "SessionStart", wantCompact)
			}
			for _, tc := range []struct {
				name string
				file []byte
			}{
				{"narrowed in place", edit(t, false, narrowed)},
				{"narrowed in place, with another edit", edit(t, true, narrowed)},
				{"a narrowed copy next to the compact group", edit(t, false, narrowed, compact)},
				{"a narrowed copy after the compact group", edit(t, false, compact, narrowed)},
			} {
				// The administrator's save is not DefenseClaw's publication.
				repaired, _, err := reconcileWindowsCodexRequirements(tc.file, current, false)
				if err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				if n, c := counts(t, repaired); n != 1 || c != 1 {
					t.Fatalf("%s: repair left %d narrowed and %d compact groups, want 1 and 1:\n%s", tc.name, n, c, repaired)
				}
				if err := verifyWindowsCodexRequirementsBytes(repaired, current); err != nil {
					t.Fatalf("%s: the repaired file does not verify: %v", tc.name, err)
				}
				// The repair's own publication, unedited since, and the
				// same file read as edited: both keep it, and change nothing.
				for _, published := range []bool{true, false} {
					again, changed, err := reconcileWindowsCodexRequirements(repaired, current, published)
					if err != nil {
						t.Fatalf("%s: %v", tc.name, err)
					}
					if n, c := counts(t, again); changed || n != 1 || c != 1 {
						t.Fatalf("%s: a second repair (published=%t) changed=%t left %d narrowed and %d compact groups:\n%s",
							tc.name, published, changed, n, c, again)
					}
				}
				cleaned, _, err := removeWindowsCodexRequirementsOwnedChanges(repaired, admin, current)
				if err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				if n, c := counts(t, cleaned); n != 0 || c != 0 {
					t.Fatalf("%s: the uninstall after the repair left %d narrowed and %d compact groups, want 0 and 0:\n%s", tc.name, n, c, cleaned)
				}
			}

			// An earlier release's own file, unedited since it published it:
			// the upgrade replaces its group, so SessionStart runs once.
			earlier := edit(t, false, narrowed)
			upgraded, _, err := reconcileWindowsCodexRequirements(earlier, current, true)
			if err != nil {
				t.Fatal(err)
			}
			if n, c := counts(t, upgraded); n != 0 || c != 1 {
				t.Fatalf("the upgrade left %d earlier and %d compact groups, want 0 and 1:\n%s", n, c, upgraded)
			}
			// That file edited since: nothing proves DefenseClaw wrote the
			// group, so a repair keeps it.
			edited := edit(t, true, narrowed)
			kept, _, err := reconcileWindowsCodexRequirements(edited, current, false)
			if err != nil {
				t.Fatal(err)
			}
			if n, c := counts(t, kept); n != 1 || c != 1 {
				t.Fatalf("an edited earlier file kept %d earlier and %d compact groups, want 1 and 1:\n%s", n, c, kept)
			}
		})
	}
}

// A repair that adopts the file (no trusted ownership record) keeps the
// narrowed SessionStart group in place. The preimage it records holds no
// DefenseClaw group, that one included: a removal takes it from any file
// (GAP-0907), so a restored preimage must not bring it back.
func TestWindowsCodexAdoptionKeepsTheNarrowedSessionStartLiveButNotInThePreimage(t *testing.T) {
	for _, contract := range KnownHookContracts("codex") {
		if !codexContractCertifiesCompactSessionStart(contract.ContractID) {
			continue
		}
		t.Run(contract.ContractID, func(t *testing.T) {
			current := testWindowsCodexMachineOptions()
			current.HookContractID = contract.ContractID
			command := windowsCodexBoundManagedHookCommand(current.HookBinary, "SessionStart", contract.ContractID)
			compact := windowsCodexTestGroup(codexCompactSessionStartMatcher, windowsCodexMachineHandler(command, 30))
			var earlierMatcher string
			for _, group := range codexHookGroups {
				if group.eventType == "SessionStart" {
					earlierMatcher = group.matcher
				}
			}
			narrowed := windowsCodexTestGroup(earlierMatcher, windowsCodexMachineHandler(command, 30))
			wantNarrowed := windowsCodexTestNormalized(t, narrowed)
			wantCompact := windowsCodexTestNormalized(t, compact)
			installed, _, err := reconcileWindowsCodexRequirements([]byte("approval_policy_floor = \"on-request\"\n"), current, true)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name   string
				groups []interface{}
			}{
				{"narrowed in place", []interface{}{narrowed}},
				{"a narrowed copy next to the compact group", []interface{}{narrowed, compact}},
			} {
				cfg, err := parseWindowsCodexRequirements(installed)
				if err != nil {
					t.Fatal(err)
				}
				cfg["hooks"].(map[string]interface{})["SessionStart"] = tc.groups
				file, err := toml.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				adoption, err := windowsCodexAdoptRequirements(file, true, nil, current)
				if err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				if n := windowsCodexTestCountGroup(t, adoption.preimage, "SessionStart", wantNarrowed); n != 0 {
					t.Fatalf("%s: the adopted preimage holds %d narrowed groups, want 0:\n%s", tc.name, n, adoption.preimage)
				}
				if c := windowsCodexTestCountGroup(t, adoption.preimage, "SessionStart", wantCompact); c != 0 {
					t.Fatalf("%s: the adopted preimage holds DefenseClaw's compact group:\n%s", tc.name, adoption.preimage)
				}
				repaired, _, err := reconcileWindowsCodexRequirements(adoption.base, current, false)
				if err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				if n, c := windowsCodexTestCountGroup(t, repaired, "SessionStart", wantNarrowed), windowsCodexTestCountGroup(t, repaired, "SessionStart", wantCompact); n != 1 || c != 1 {
					t.Fatalf("%s: the adopting repair left %d narrowed and %d compact groups, want 1 and 1:\n%s", tc.name, n, c, repaired)
				}
			}
		})
	}
}
