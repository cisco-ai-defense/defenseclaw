// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// windowsCodexTestGroup is a Windows Codex machine group with one handler.
func windowsCodexTestGroup(matcher string, handler map[string]interface{}) map[string]interface{} {
	group := map[string]interface{}{"hooks": []interface{}{handler}}
	if matcher != "" {
		group["matcher"] = matcher
	}
	return group
}

// windowsCodexTestNormalized is group as it reads back from a requirements
// file, so it compares with what reconcile and removal leave.
func windowsCodexTestNormalized(t *testing.T, group map[string]interface{}) interface{} {
	t.Helper()
	raw, err := toml.Marshal(map[string]interface{}{"hooks": map[string]interface{}{"E": []interface{}{group}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cfg["hooks"].(map[string]interface{})["E"].([]interface{})[0]
}

// windowsCodexTestCountGroup counts the groups under hooks.<event> of raw
// equal to want.
func windowsCodexTestCountGroup(t *testing.T, raw []byte, event string, want interface{}) int {
	t.Helper()
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	groups, _ := hooks[event].([]interface{})
	found := 0
	for _, group := range groups {
		if reflect.DeepEqual(group, want) {
			found++
		}
	}
	return found
}

// windowsCodexTestWithGroup is the file DefenseClaw renders for opts over
// the administrator's base, with group added under hooks.<event> (built
// without reconcile so removal is checked on its own).
func windowsCodexTestWithGroup(t *testing.T, opts WindowsCodexMachineRequirementsOptions, event string, group map[string]interface{}) []byte {
	t.Helper()
	rendered, _, err := reconcileWindowsCodexRequirements([]byte("approval_policy_floor = \"on-request\"\n"), opts, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseWindowsCodexRequirements(rendered)
	if err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	existing, _ := hooks[event].([]interface{})
	hooks[event] = append([]interface{}{group}, existing...)
	raw, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A group that runs DefenseClaw's own managed command but is not a group
// DefenseClaw renders (an administrator edited its matcher, its timeout or a
// key, added a handler, or moved it under another event) is the
// administrator's. A standalone uninstall used to delete it (ownership
// looked only at the command), and reconcile, the stale-layout strip and
// stale-layout inference took it the same way. Every one of them now leaves
// it, the removal reports no DefenseClaw leftover, and the group's reference
// to the launcher keeps the binary removal unsafe. The unedited group of
// every shape stays DefenseClaw's.
func TestWindowsCodexLifecycleKeepsAnAdministratorEditedDefenseClawGroup(t *testing.T) {
	contracts := KnownHookContracts("codex")
	current := testWindowsCodexMachineOptions()
	current.HookContractID = contracts[len(contracts)-1].ContractID
	earlier := testWindowsCodexMachineOptions()
	earlier.HookContractID = contracts[0].ContractID
	if codexContractCertifiesCompactSessionStart(earlier.HookContractID) {
		t.Fatalf("%s certifies the compact SessionStart source; the test needs one that does not", earlier.HookContractID)
	}
	if !codexContractCertifiesCompactSessionStart(current.HookContractID) {
		t.Fatalf("%s does not certify the compact SessionStart source", current.HookContractID)
	}
	bin := current.HookBinary
	bound := func(event, contract string) string { return windowsCodexBoundManagedHookCommand(bin, event, contract) }
	handler := func(command string, timeout int) map[string]interface{} {
		return windowsCodexMachineHandler(command, timeout)
	}
	with := func(base map[string]interface{}, key string, value interface{}) map[string]interface{} {
		edited := map[string]interface{}{}
		for k, v := range base {
			edited[k] = v
		}
		edited[key] = value
		return edited
	}
	preToolUse := bound("PreToolUse", current.HookContractID)

	edited := []struct {
		name, event string
		group       map[string]interface{}
	}{
		{"another matcher", "PreToolUse", windowsCodexTestGroup("Bash", handler(preToolUse, 30))},
		{"its matcher removed", "PreToolUse", windowsCodexTestGroup("", handler(preToolUse, 30))},
		{"a matcher added", "UserPromptSubmit", windowsCodexTestGroup("*", handler(bound("UserPromptSubmit", current.HookContractID), 30))},
		{"another timeout", "PreToolUse", windowsCodexTestGroup("*", handler(preToolUse, 5))},
		{"another Stop timeout", "Stop", windowsCodexTestGroup("", handler(bound("Stop", current.HookContractID), 30))},
		{"an extra handler key", "PreToolUse", windowsCodexTestGroup("*", with(handler(preToolUse, 30), "statusMessage", "audited"))},
		{"another command_windows", "PreToolUse", windowsCodexTestGroup("*", with(handler(preToolUse, 30), "command_windows", `C:\Tools\audit.exe`))},
		{"an extra group key", "PreToolUse", with(windowsCodexTestGroup("*", handler(preToolUse, 30)), "description", "audited")},
		{"a second handler", "PreToolUse", map[string]interface{}{"matcher": "*", "hooks": []interface{}{
			handler(preToolUse, 30),
			map[string]interface{}{"type": "command", "command": `C:\Tools\audit.exe`, "timeout": 5},
		}}},
		{"one event's command under another event", "PostToolUse", windowsCodexTestGroup("*", handler(preToolUse, 30))},
		{"under an event no release hooks", "SessionEnd", windowsCodexTestGroup("", handler(bound("SessionEnd", current.HookContractID), 3))},
		{"the compact matcher on a contract that does not certify it", "SessionStart",
			windowsCodexTestGroup(codexCompactSessionStartMatcher, handler(bound("SessionStart", earlier.HookContractID), 30))},
		{"the 1.0.0 command with another timeout", "PreToolUse",
			windowsCodexTestGroup("*", handler(legacyStartProcessWindowsCodexBoundManagedHookCommand(bin, "PreToolUse", current.HookContractID), 60))},
		{"the unbound command with another matcher", "PreToolUse", windowsCodexTestGroup("Bash", handler(windowsCodexManagedHookCommand(bin), 30))},
	}
	adminFileFor := func(t *testing.T, event string, group map[string]interface{}) []byte {
		t.Helper()
		raw, err := toml.Marshal(map[string]interface{}{
			"approval_policy_floor": "on-request",
			"hooks":                 map[string]interface{}{event: []interface{}{group}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, tc := range edited {
		t.Run(tc.name, func(t *testing.T) {
			want := windowsCodexTestNormalized(t, tc.group)
			adminFile := adminFileFor(t, tc.event, tc.group)
			written := windowsCodexTestWithGroup(t, earlier, tc.event, tc.group)
			upgraded := windowsCodexTestWithGroup(t, current, tc.event, tc.group)
			for _, install := range []struct {
				name string
				file []byte
			}{
				{"install over the administrator file", adminFile},
				{"upgrade from the earlier release", written},
				{"repair of the current release", upgraded},
			} {
				reconciled, _, err := reconcileWindowsCodexRequirements(install.file, current, true)
				if err != nil {
					t.Fatalf("%s: %v", install.name, err)
				}
				if got := windowsCodexTestCountGroup(t, reconciled, tc.event, want); got != 1 {
					t.Errorf("%s left %d copies of the administrator group, want 1:\n%s", install.name, got, reconciled)
				}
			}
			for _, removal := range []struct {
				name           string
				file, baseline []byte
			}{
				{"earlier release over the administrator preimage", written, adminFile},
				{"earlier release recorded as its own preimage", written, written},
				{"current release over the administrator preimage", upgraded, adminFile},
				{"current release recorded as its own preimage", upgraded, upgraded},
			} {
				cleaned, _, err := removeWindowsCodexRequirementsOwnedChanges(removal.file, removal.baseline, current)
				if err != nil {
					t.Fatalf("%s: %v", removal.name, err)
				}
				if got := windowsCodexTestCountGroup(t, cleaned, tc.event, want); got != 1 {
					t.Errorf("%s: uninstall left %d copies of the administrator group, want 1:\n%s", removal.name, got, cleaned)
					continue
				}
				if leftovers, err := windowsCodexRequirementsHoldOwnedLeftovers(cleaned, current); err != nil || leftovers {
					t.Errorf("%s: DefenseClaw content left = %t, %v:\n%s", removal.name, leftovers, err, cleaned)
				}
				references, err := windowsCodexOwnedPathReferenceCount(cleaned, current)
				if err != nil {
					t.Fatal(err)
				}
				if references == 0 {
					t.Errorf("%s: the administrator group's reference to the launcher does not keep the binary:\n%s", removal.name, cleaned)
				}
			}
			stripped, _, err := stripWindowsCodexLayout(upgraded, current.HookBinary, current.ManagedDir)
			if err != nil {
				t.Fatal(err)
			}
			if got := windowsCodexTestCountGroup(t, stripped, tc.event, want); got != 1 {
				t.Errorf("the layout strip left %d copies of the administrator group, want 1:\n%s", got, stripped)
			}
		})
	}

	// Stale-layout inference adopts a prior directory only on a group
	// DefenseClaw renders for that directory's launcher.
	stale := current
	stale.HookBinary = `C:\Old\DefenseClaw\bin\defenseclaw-hook.exe`
	staleFile := func(t *testing.T, group map[string]interface{}) []byte {
		t.Helper()
		raw, err := toml.Marshal(map[string]interface{}{"hooks": map[string]interface{}{
			"windows_managed_dir": `C:\Old\DefenseClaw\bin`,
			"PreToolUse":          []interface{}{group},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	staleCommand := windowsCodexBoundManagedHookCommand(stale.HookBinary, "PreToolUse", current.HookContractID)
	if dir, _ := windowsCodexUnrecordedStaleLayout(staleFile(t, windowsCodexTestGroup("*", handler(staleCommand, 30))), current); dir == "" {
		t.Fatal("inference does not adopt a prior directory on DefenseClaw's own group")
	}
	if dir, _ := windowsCodexUnrecordedStaleLayout(staleFile(t, windowsCodexTestGroup("Bash", handler(staleCommand, 30))), current); dir != "" {
		t.Errorf("inference adopted %q on an administrator-edited group", dir)
	}

	// Every unedited shape is still DefenseClaw's: the compact SessionStart
	// matcher of a certifying contract, the shared matrix of an earlier
	// contract, the 1.0.0 form and the unbound command. The SessionStart
	// matcher before the compact source, around the current command, is
	// TestWindowsCodexUninstallKeepsAnAdministratorNarrowedSessionStart.
	for _, owned := range []struct {
		name, event string
		group       map[string]interface{}
	}{
		{"current compact SessionStart", "SessionStart", windowsCodexTestGroup(codexCompactSessionStartMatcher, handler(bound("SessionStart", current.HookContractID), 30))},
		{"earlier contract Stop", "Stop", windowsCodexTestGroup("", handler(bound("Stop", earlier.HookContractID), 90))},
		{"1.0.0 PreToolUse", "PreToolUse", windowsCodexTestGroup("*", handler(legacyStartProcessWindowsCodexBoundManagedHookCommand(bin, "PreToolUse", earlier.HookContractID), 30))},
		{"unbound SubagentStop", "SubagentStop", windowsCodexTestGroup("*", handler(windowsCodexManagedHookCommand(bin), 90))},
	} {
		t.Run("owned "+owned.name, func(t *testing.T) {
			want := windowsCodexTestNormalized(t, owned.group)
			file := windowsCodexTestWithGroup(t, current, owned.event, owned.group)
			if leftovers, err := windowsCodexRequirementsHoldOwnedLeftovers(file, current); err != nil || !leftovers {
				t.Fatalf("DefenseClaw's group is not recognized = %t, %v", leftovers, err)
			}
			cleaned, _, err := removeWindowsCodexRequirementsOwnedChanges(file, adminFileFor(t, "Other", windowsCodexTestGroup("", map[string]interface{}{"type": "command", "command": "audit.exe"})), current)
			if err != nil {
				t.Fatal(err)
			}
			if got := windowsCodexTestCountGroup(t, cleaned, owned.event, want); got != 0 {
				t.Errorf("uninstall kept DefenseClaw's group:\n%s", cleaned)
			}
			stripped, _, err := stripWindowsCodexLayout(file, current.HookBinary, current.ManagedDir)
			if err != nil {
				t.Fatal(err)
			}
			if got := windowsCodexTestCountGroup(t, stripped, owned.event, want); got != 0 {
				t.Errorf("the layout strip kept DefenseClaw's group:\n%s", stripped)
			}
		})
	}
}

// Loop round 5 review: an administrator who cuts the compact source from
// this install's SessionStart matcher gets, byte for byte, the group a
// release before the compact matcher rendered around the same command. The
// uninstall took it as that release's group (its count-based removal and its
// any-release sweep), so it deleted the administrator's edit. A removal now
// takes this install's own command only in the group this install renders,
// or in a group the recorded preimage holds (the earlier release's own
// entry, GAP-0907); the edited group stays, no DefenseClaw content is
// reported left, and its reference to the managed directory keeps the binary
// removal unsafe. An upgrade still replaces the earlier release's group, and
// the layout strip still takes it.
func TestWindowsCodexUninstallKeepsAnAdministratorNarrowedSessionStart(t *testing.T) {
	contracts := KnownHookContracts("codex")
	for _, contract := range contracts {
		if !codexContractCertifiesCompactSessionStart(contract.ContractID) {
			continue
		}
		t.Run(contract.ContractID, func(t *testing.T) {
			current := testWindowsCodexMachineOptions()
			current.HookContractID = contract.ContractID
			command := windowsCodexBoundManagedHookCommand(current.HookBinary, "SessionStart", contract.ContractID)
			compact := windowsCodexTestGroup(codexCompactSessionStartMatcher, windowsCodexMachineHandler(command, 30))
			var narrowedMatcher string
			for _, group := range codexHookGroups {
				if group.eventType == "SessionStart" {
					narrowedMatcher = group.matcher
				}
			}
			if narrowedMatcher == "" || narrowedMatcher == codexCompactSessionStartMatcher {
				t.Fatalf("the earlier SessionStart matcher %q is not an earlier shape", narrowedMatcher)
			}
			narrowed := windowsCodexTestGroup(narrowedMatcher, windowsCodexMachineHandler(command, 30))
			wantNarrowed := windowsCodexTestNormalized(t, narrowed)
			wantCompact := windowsCodexTestNormalized(t, compact)
			admin := []byte("approval_policy_floor = \"on-request\"\n")
			rendered, _, err := reconcileWindowsCodexRequirements(admin, current, true)
			if err != nil {
				t.Fatal(err)
			}
			if windowsCodexTestCountGroup(t, rendered, "SessionStart", wantCompact) != 1 {
				t.Fatalf("the current release does not render the compact SessionStart group:\n%s", rendered)
			}
			// The administrator's edit: the compact group with its matcher narrowed.
			editedFile := func(t *testing.T, keepCompact bool) []byte {
				t.Helper()
				cfg, err := parseWindowsCodexRequirements(rendered)
				if err != nil {
					t.Fatal(err)
				}
				hooks := cfg["hooks"].(map[string]interface{})
				groups := []interface{}{narrowed}
				if keepCompact {
					groups = append(groups, compact)
				}
				hooks["SessionStart"] = groups
				raw, err := toml.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			for _, tc := range []struct {
				name     string
				file     []byte
				baseline []byte
			}{
				{"edited in place, over the administrator preimage", editedFile(t, false), admin},
				{"edited in place, over an empty preimage", editedFile(t, false), nil},
				{"a narrowed copy next to the compact group", editedFile(t, true), admin},
			} {
				cleaned, _, err := removeWindowsCodexRequirementsOwnedChanges(tc.file, tc.baseline, current)
				if err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				if got := windowsCodexTestCountGroup(t, cleaned, "SessionStart", wantNarrowed); got != 1 {
					t.Errorf("%s: uninstall left %d copies of the administrator SessionStart group, want 1:\n%s", tc.name, got, cleaned)
					continue
				}
				if got := windowsCodexTestCountGroup(t, cleaned, "SessionStart", wantCompact); got != 0 {
					t.Errorf("%s: uninstall kept DefenseClaw's compact group:\n%s", tc.name, cleaned)
				}
				if leftovers, err := windowsCodexRequirementsHoldOwnedLeftovers(cleaned, current); err != nil || leftovers {
					t.Errorf("%s: DefenseClaw content left = %t, %v:\n%s", tc.name, leftovers, err, cleaned)
				}
				if exact, err := windowsCodexRequirementsContainExactManagedHook(cleaned, current); err != nil || exact {
					t.Errorf("%s: an exact DefenseClaw group is reported left = %t, %v:\n%s", tc.name, exact, err, cleaned)
				}
				if references, err := windowsCodexOwnedPathReferenceCount(cleaned, current); err != nil || references == 0 {
					t.Errorf("%s: references = %d, %v; the administrator group must keep the binary:\n%s", tc.name, references, err, cleaned)
				}
			}

			// The earlier release's own file, with that matcher around the
			// same command: an upgrade replaces its group, the layout strip
			// takes it, and an uninstall whose preimage records it removes it.
			earlierFile := editedFile(t, false)
			upgraded, _, err := reconcileWindowsCodexRequirements(earlierFile, current, true)
			if err != nil {
				t.Fatal(err)
			}
			if windowsCodexTestCountGroup(t, upgraded, "SessionStart", wantNarrowed) != 0 ||
				windowsCodexTestCountGroup(t, upgraded, "SessionStart", wantCompact) != 1 {
				t.Errorf("the upgrade did not replace the earlier SessionStart group with the compact one:\n%s", upgraded)
			}
			stripped, _, err := stripWindowsCodexLayout(earlierFile, current.HookBinary, current.ManagedDir)
			if err != nil {
				t.Fatal(err)
			}
			if windowsCodexTestCountGroup(t, stripped, "SessionStart", wantNarrowed) != 0 {
				t.Errorf("the layout strip kept the earlier SessionStart group:\n%s", stripped)
			}
			for _, removal := range []struct {
				name           string
				file, baseline []byte
			}{
				{"recorded as its own preimage", earlierFile, earlierFile},
				{"recorded in the preimage, upgraded since", upgraded, earlierFile},
			} {
				cleaned, _, err := removeWindowsCodexRequirementsOwnedChanges(removal.file, removal.baseline, current)
				if err != nil {
					t.Fatalf("%s: %v", removal.name, err)
				}
				if strings.Contains(string(cleaned), "EncodedCommand") {
					t.Errorf("%s: a DefenseClaw group survived the removal:\n%s", removal.name, cleaned)
				}
				if leftovers, err := windowsCodexRequirementsHoldOwnedLeftovers(cleaned, current); err != nil || leftovers {
					t.Errorf("%s: DefenseClaw content left = %t, %v:\n%s", removal.name, leftovers, err, cleaned)
				}
			}
		})
	}
}
