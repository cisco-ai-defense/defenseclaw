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
// Uninstall keeps it as the administrator's (round 5), but reconcile took it
// as that release's group, so every repair deleted it. Reconcile now replaces
// it only in a file nobody edited since DefenseClaw published it that holds
// no exact group of this install: an upgrade from 1.0.2 or 1.0.3. Every
// other copy stays next to the exact group, through repeated repairs, and
// the uninstall that follows still keeps it.
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
				if n, c := counts(t, cleaned); n != 1 || c != 0 {
					t.Fatalf("%s: the uninstall after the repair left %d narrowed and %d compact groups, want 1 and 0:\n%s", tc.name, n, c, cleaned)
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
			// group, so it stays (the safe side; uninstall keeps it too).
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
