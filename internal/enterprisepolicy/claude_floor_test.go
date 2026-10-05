// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const wantClaudeFloorBytes = "{\n  \"requiredMinimumVersion\": \"2.1.154\"\n}\n"

func claudeFloorFile(t *testing.T, opts Options) string {
	t.Helper()
	path, err := ClaudeVersionFloorPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func hasDetail(state State, substring string) bool {
	for _, detail := range state.Details {
		if strings.Contains(detail, substring) {
			return true
		}
	}
	return false
}

func floorConflicts(state State) []string {
	var out []string
	for _, conflict := range state.Conflicts {
		if strings.Contains(conflict, "version floor") {
			out = append(out, conflict)
		}
	}
	return out
}

func reconcileClaude(t *testing.T, opts Options) State {
	t.Helper()
	state, err := claudeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// The floor is its own drop-in: the hook drop-in keeps its exact bytes and
// never carries requiredMinimumVersion.
func TestClaudeVersionFloorWrittenWhenNoSourceSetsIt(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	adminSettings := `{"permissions": {"deny": ["Bash(rm -rf /)"]}}` + "\n"
	base := filepath.Join(claudeDir(t, opts), "managed-settings.json")
	writeFile(t, base, adminSettings)

	state := reconcileClaude(t, opts)
	mustNoConflicts(t, state)
	if got := readFile(t, claudeFloorFile(t, opts)); got != wantClaudeFloorBytes {
		t.Fatalf("floor drop-in = %q, want %q", got, wantClaudeFloorBytes)
	}
	if filepath.Base(claudeFloorFile(t, opts)) != "00-defenseclaw-version-floor.json" {
		t.Fatalf("floor drop-in name = %s", claudeFloorFile(t, opts))
	}
	hooks, err := renderClaudeDropIn(opts, opts.PolicyFor("claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	dropIn := readFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.d", DefenseClawDropInName))
	if dropIn != string(hooks) || strings.Contains(dropIn, "requiredMinimumVersion") {
		t.Fatalf("the hook drop-in must stay the unchanged hook rendering:\n%s", dropIn)
	}
	if readFile(t, base) != adminSettings {
		t.Fatal("administrator managed-settings.json changed")
	}
	floor := state.VersionFloor
	if floor == nil || floor.Owner != VersionFloorOwnerDefenseClaw || floor.Value != "2.1.154" || floor.Mode != "enforce" || floor.Source != claudeFloorFile(t, opts) {
		t.Fatalf("floor state: %+v", floor)
	}
	if !strings.Contains(floor.Summary(), "set by DefenseClaw") {
		t.Fatalf("summary: %s", floor.Summary())
	}
	if again := reconcileClaude(t, opts); again.Changed {
		t.Fatalf("a second reconcile must be a no-op: %+v", again)
	}
	if recorded, err := ClaudeVersionFloorRecorded(opts); err != nil || !recorded {
		t.Fatalf("floor ownership record: %v %v", recorded, err)
	}

	// Removal deletes a floor DefenseClaw wrote, and the drop-in directory it
	// created for it.
	t.Run("removal", func(t *testing.T) {
		withHigherSources(t)
		opts := testOptions(t)
		reconcileClaude(t, opts)
		if _, err := (claudeTarget{}).RemoveOwned(opts); err != nil {
			t.Fatal(err)
		}
		if fileExists(claudeFloorFile(t, opts)) {
			t.Fatal("removal must delete a floor DefenseClaw wrote")
		}
		if fileExists(filepath.Join(claudeDir(t, opts), "managed-settings.d")) {
			t.Fatal("removal must also remove the drop-in directory DefenseClaw created")
		}
		if recorded, _ := ClaudeVersionFloorRecorded(opts); recorded {
			t.Fatal("removal must delete the floor record")
		}
	})
}

// An administrator value in the base file, any drop-in (one sorting before
// DefenseClaw's included) or a higher-precedence source is kept byte for
// byte, DefenseClaw withdraws its own drop-in at the next reconcile, and the
// floor returns when the administrator removes the key.
func TestClaudeVersionFloorKeepsAnAdministratorValue(t *testing.T) {
	cases := []struct {
		name   string
		file   string
		higher bool
		// after: Claude Code merges the file after DefenseClaw's
		// 00-defenseclaw-version-floor.json (drop-ins merge in name order).
		after bool
	}{
		// "-" sorts before "0", so "000-" sorts after "00-".
		{name: "later numbered drop-in", file: "managed-settings.d/000-company.json", after: true},
		// This sorts before 00-defenseclaw-version-floor.json: DefenseClaw's
		// drop-in would replace its value, so it is withdrawn.
		{name: "earlier drop-in", file: "managed-settings.d/00-admin.json"},
		{name: "higher-precedence source", higher: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withHigherSources(t)
			opts := testOptions(t)
			reconcileClaude(t, opts)
			if !fileExists(claudeFloorFile(t, opts)) {
				t.Fatal("floor not written before the administrator sets the key")
			}
			admin := `{"requiredMinimumVersion": "2.1.200", "env": {"COMPANY": "1"}}` + "\n"
			source := `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`
			if tc.higher {
				withHigherSources(t, higherSource(t, source, `{"requiredMinimumVersion": "2.1.200", "managedSourcesBehavior": "merge"}`))
			} else {
				source = path.Join(claudeDir(t, opts), tc.file)
				if sortsAfter := strings.HasPrefix(tc.file, "managed-settings.d/") && path.Base(tc.file) > ClaudeVersionFloorDropInName; sortsAfter != tc.after {
					t.Fatalf("%s sorts after %s = %v, the case says %v", tc.file, ClaudeVersionFloorDropInName, sortsAfter, tc.after)
				}
				if got := claudeDropInSortsAfterFloor(opts, source); got != tc.after {
					t.Fatalf("claudeDropInSortsAfterFloor(%s) = %v, want %v", tc.file, got, tc.after)
				}
				writeFile(t, source, admin)
			}
			state := reconcileClaude(t, opts)
			if conflicts := floorConflicts(state); len(conflicts) != 0 {
				t.Fatalf("an administrator value is not a conflict: %v", conflicts)
			}
			if fileExists(claudeFloorFile(t, opts)) {
				t.Fatal("DefenseClaw's floor must be withdrawn once an administrator source sets the key")
			}
			if recorded, _ := ClaudeVersionFloorRecorded(opts); recorded {
				t.Fatal("the floor record must go with the drop-in")
			}
			if !tc.higher && readFile(t, source) != admin {
				t.Fatal("the administrator's file must be untouched")
			}
			floor := state.VersionFloor
			if floor == nil || floor.Owner != VersionFloorOwnerAdministrator || floor.Source != source || floor.Value != "2.1.200" || floor.BelowFloor || floor.Invalid {
				t.Fatalf("floor state: %+v", floor)
			}
			if !hasDetail(state, "keeps the administrator's value") {
				t.Fatalf("the administrator value must be reported: %v", state.Details)
			}
			if verify, err := (claudeTarget{}).Verify(opts); err != nil || len(floorConflicts(verify)) != 0 || verify.VersionFloor.Owner != VersionFloorOwnerAdministrator {
				t.Fatalf("verify: %v %+v", err, verify)
			}

			if tc.higher {
				withHigherSources(t, higherSource(t, source, `{"managedSourcesBehavior": "merge"}`))
			} else if err := os.Remove(source); err != nil {
				t.Fatal(err)
			}
			reconcileClaude(t, opts)
			if readFile(t, claudeFloorFile(t, opts)) != wantClaudeFloorBytes {
				t.Fatal("the floor must come back when no administrator source sets the key")
			}
		})
	}
}

// A version below the floor is the administrator's choice: it is kept and
// reported. A value that is not a version is ignored by Claude Code, so it
// never counts as a floor: in a file that merges before DefenseClaw's
// drop-in (the base file, or a drop-in whose name sorts before it), the
// drop-in stays (its later value applies), verify passes, and the
// administrator file is untouched.
func TestClaudeVersionFloorReportsBelowFloorAndInvalidValues(t *testing.T) {
	for _, file := range []string{"managed-settings.json", "managed-settings.d/00-admin.json"} {
		for _, tc := range []struct {
			value   string
			below   bool
			invalid bool
			note    string
		}{
			{value: `"2.1.100"`, below: true, note: "below 2.1.154"},
			{value: `"latest"`, invalid: true, note: "Claude Code ignores it and applies DefenseClaw's value"},
			{value: `5`, invalid: true, note: "Claude Code ignores it and applies DefenseClaw's value"},
			{value: `"3.0.0"`, note: "keeps the administrator's value"},
		} {
			t.Run(file+" "+tc.value, func(t *testing.T) {
				withHigherSources(t)
				opts := testOptions(t)
				source := path.Join(claudeDir(t, opts), file) // the rooted tree's own join
				admin := `{"requiredMinimumVersion": ` + tc.value + `}`
				writeFile(t, source, admin)
				state := reconcileClaude(t, opts)
				floor := state.VersionFloor
				if !hasDetail(state, tc.note) || len(floorConflicts(state)) != 0 {
					t.Fatalf("details %v conflicts %v", state.Details, state.Conflicts)
				}
				if readFile(t, source) != admin {
					t.Fatal("the administrator's file must be untouched")
				}
				if tc.invalid {
					if floor == nil || floor.Owner != VersionFloorOwnerDefenseClaw || floor.Value != "2.1.154" || floor.OverriddenSource != source || floor.Overridden == "" {
						t.Fatalf("an invalid administrator value merged first must not remove the floor: %+v", floor)
					}
					if readFile(t, claudeFloorFile(t, opts)) != wantClaudeFloorBytes {
						t.Fatal("DefenseClaw's floor drop-in must stay in place")
					}
					if verify, err := (claudeTarget{}).Verify(opts); err != nil || len(floorConflicts(verify)) != 0 || !verify.Covered {
						t.Fatalf("verify: %v %v", err, verify.Conflicts)
					}
					return
				}
				if floor == nil || floor.Owner != VersionFloorOwnerAdministrator || floor.BelowFloor != tc.below || floor.Invalid {
					t.Fatalf("floor state: %+v", floor)
				}
				if fileExists(claudeFloorFile(t, opts)) {
					t.Fatal("an administrator version, even a low one, is never overridden")
				}
			})
		}
	}
}

// A value that is not a version in a source that merges after DefenseClaw's
// drop-in (a later drop-in, a higher-precedence source) replaces the floor,
// and Claude Code then ignores it: no floor applies. Under enforce and merge
// that fails verify; DefenseClaw never edits the source.
func TestClaudeVersionFloorInvalidValueAfterTheDropInFailsVerify(t *testing.T) {
	const hklm = `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`
	for _, higher := range []bool{false, true} {
		t.Run(map[bool]string{false: "later drop-in", true: "higher-precedence source"}[higher], func(t *testing.T) {
			withHigherSources(t)
			opts := testOptions(t)
			reconcileClaude(t, opts)
			source := path.Join(claudeDir(t, opts), "managed-settings.d", "10-company.json")
			admin := `{"requiredMinimumVersion": "latest"}`
			if higher {
				source = hklm
				withHigherSources(t, higherSource(t, hklm, `{"requiredMinimumVersion": "latest", "managedSourcesBehavior": "merge"}`))
			} else {
				writeFile(t, source, admin)
			}
			state := reconcileClaude(t, opts)
			floor := state.VersionFloor
			if floor == nil || floor.Owner != VersionFloorOwnerAdministrator || !floor.Invalid || floor.Source != source {
				t.Fatalf("floor state: %+v", floor)
			}
			if fileExists(claudeFloorFile(t, opts)) || (!higher && readFile(t, source) != admin) {
				t.Fatal("the administrator source wins and stays untouched; DefenseClaw's drop-in is withdrawn")
			}
			verify, err := claudeTarget{}.Verify(opts)
			if err != nil || len(floorConflicts(verify)) != 1 || !hasConflict(verify, "not a major.minor.patch version") || verify.Covered {
				t.Fatalf("an invalid administrator floor that outranks DefenseClaw's must fail verify: %v %v", err, verify.Conflicts)
			}

			report := testOptions(t)
			report.ClaudeVersionFloor = config.ClaudeVersionFloorReport
			if !higher {
				writeFile(t, path.Join(claudeDir(t, report), "managed-settings.d", "10-company.json"), admin)
			}
			if state := reconcileClaude(t, report); len(floorConflicts(state)) != 0 || !hasDetail(state, "not a major.minor.patch version") {
				t.Fatalf("report only reports: %v %v", state.Conflicts, state.Details)
			}
		})
	}
}

func TestClaudeVersionFloorModes(t *testing.T) {
	withHigherSources(t)

	report := testOptions(t)
	report.ClaudeVersionFloor = config.ClaudeVersionFloorReport
	state := reconcileClaude(t, report)
	if fileExists(claudeFloorFile(t, report)) || len(floorConflicts(state)) != 0 || !hasDetail(state, "version_floor: report") {
		t.Fatalf("report must only report: %+v", state)
	}

	off := testOptions(t)
	off.ClaudeVersionFloor = config.ClaudeVersionFloorOff
	state = reconcileClaude(t, off)
	if fileExists(claudeFloorFile(t, off)) || len(floorConflicts(state)) != 0 || state.VersionFloor.Mode != "off" {
		t.Fatalf("off must not write: %+v", state)
	}

	// Moving from enforce to report or off withdraws DefenseClaw's floor.
	opts := testOptions(t)
	reconcileClaude(t, opts)
	opts.ClaudeVersionFloor = config.ClaudeVersionFloorReport
	if state = reconcileClaude(t, opts); fileExists(claudeFloorFile(t, opts)) || !state.Changed {
		t.Fatalf("report must withdraw the floor: %+v", state)
	}

	// verify_only never writes; a missing floor is then advice, not a conflict.
	verifyOnly := withPolicy(testOptions(t), "claudecode", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = "verify_only" })
	state = reconcileClaude(t, verifyOnly)
	if fileExists(claudeFloorFile(t, verifyOnly)) || len(floorConflicts(state)) != 0 || !hasDetail(state, "--format version-floor") {
		t.Fatalf("verify_only: %+v", state)
	}

	// Under enforce a missing floor fails verification.
	enforce := testOptions(t)
	reconcileClaude(t, enforce)
	if err := os.Remove(claudeFloorFile(t, enforce)); err != nil {
		t.Fatal(err)
	}
	verify, err := claudeTarget{}.Verify(enforce)
	if err != nil || len(floorConflicts(verify)) != 1 || verify.Covered {
		t.Fatalf("a missing floor must be a conflict: %v %+v", err, verify.Conflicts)
	}
	if verify.OwnedEntries == 0 {
		t.Fatal("a missing floor must not hide the published hooks")
	}
}

// requireUnrecordedFloorFile fails unless the file under DefenseClaw's floor
// name still holds want and DefenseClaw records no floor.
func requireUnrecordedFloorFile(t *testing.T, opts Options, want, step string) {
	t.Helper()
	if got := readFile(t, claudeFloorFile(t, opts)); got != want {
		t.Fatalf("%s changed the administrator's %s: %q", step, ClaudeVersionFloorDropInName, got)
	}
	if recorded, err := ClaudeVersionFloorRecorded(opts); err != nil || recorded {
		t.Fatalf("%s recorded the administrator's file as DefenseClaw's: %v %v", step, recorded, err)
	}
}

// A file under DefenseClaw's floor name without DefenseClaw's record is the
// administrator's, even in DefenseClaw's exact rendering: the
// `version-floor` export they deployed, at the floor or any other version.
// Under every version_floor mode and under verify_only it stays byte for
// byte through reconcile, verify and removal, and it is reported as the
// administrator's, never as set by DefenseClaw.
func TestClaudeVersionFloorLeavesAnUnrecordedAdministratorFloor(t *testing.T) {
	modes := []struct {
		name      string
		mode      string
		ownership string
	}{
		{name: "enforce", mode: config.ClaudeVersionFloorEnforce},
		{name: "report", mode: config.ClaudeVersionFloorReport},
		{name: "off", mode: config.ClaudeVersionFloorOff},
		{name: "verify_only", mode: config.ClaudeVersionFloorEnforce, ownership: config.MachinePolicyOwnershipVerifyOnly},
	}
	values := []struct{ version, file string }{
		{version: "2.1.154", file: wantClaudeFloorBytes},
		{version: "2.1.200", file: "{\n  \"requiredMinimumVersion\": \"2.1.200\"\n}\n"},
		{version: "2.1.100", file: "{\n  \"requiredMinimumVersion\": \"2.1.100\"\n}\n"},
	}
	for _, m := range modes {
		for _, v := range values {
			t.Run(m.name+" "+v.version, func(t *testing.T) {
				withHigherSources(t)
				opts := testOptions(t)
				if m.ownership != "" {
					opts = withPolicy(opts, "claudecode", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = m.ownership })
				}
				opts.ClaudeVersionFloor = m.mode
				if exported, err := (claudeTarget{}).Export(testOptions(t), "version-floor"); err != nil || string(exported) != wantClaudeFloorBytes {
					t.Fatalf("the export is the file an administrator deploys: %v %q", err, exported)
				}
				writeFile(t, claudeFloorFile(t, opts), v.file)

				for i := 0; i < 2; i++ {
					state := reconcileClaude(t, opts)
					requireUnrecordedFloorFile(t, opts, v.file, "reconcile")
					if hasDetail(state, "removed") || hasDetail(state, "restored") {
						t.Fatalf("reconcile reported removing the administrator's file: %v", state.Details)
					}
					if len(floorConflicts(state)) != 0 {
						t.Fatalf("an administrator version is not a conflict: %v", state.Conflicts)
					}
					floor := state.VersionFloor
					if floor == nil || floor.Owner != VersionFloorOwnerAdministrator || floor.Source != claudeFloorFile(t, opts) || floor.Value != v.version || floor.BelowFloor != (v.version == "2.1.100") {
						t.Fatalf("floor state: %+v", floor)
					}
					if summary := floor.Summary(); strings.Contains(summary, "set by DefenseClaw") || !strings.Contains(summary, "set by the administrator") {
						t.Fatalf("summary: %s", summary)
					}
				}
				verify, err := claudeTarget{}.Verify(opts)
				if err != nil || len(floorConflicts(verify)) != 0 || verify.VersionFloor.Owner != VersionFloorOwnerAdministrator {
					t.Fatalf("verify: %v %v %+v", err, verify.Conflicts, verify.VersionFloor)
				}
				requireUnrecordedFloorFile(t, opts, v.file, "verify")
				removed, err := claudeTarget{}.RemoveOwned(opts)
				if err != nil {
					t.Fatal(err)
				}
				requireUnrecordedFloorFile(t, opts, v.file, "removal")
				if !hasDetail(removed, "has no record of writing it") {
					t.Fatalf("removal must say why it kept the file: %v", removed.Details)
				}
			})
		}
	}

	// Any other content under DefenseClaw's floor name is also the
	// administrator's: DefenseClaw never rewrites it to place its floor. Under
	// enforce and merge no floor applies, so verify fails and says how to fix it;
	// report only reports; removal leaves the file.
	t.Run("any content under the name", func(t *testing.T) {
		for _, tc := range []struct {
			name, content, conflict string
		}{
			{name: "other settings", content: `{"env": {"COMPANY": "1"}}` + "\n", conflict: "holds a file DefenseClaw did not write"},
			{name: "invalid value", content: `{"requiredMinimumVersion": "latest"}` + "\n", conflict: "a file DefenseClaw did not write under its drop-in name"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				withHigherSources(t)
				opts := testOptions(t)
				writeFile(t, claudeFloorFile(t, opts), tc.content)
				state := reconcileClaude(t, opts)
				requireUnrecordedFloorFile(t, opts, tc.content, "reconcile")
				if conflicts := floorConflicts(state); len(conflicts) != 1 || !strings.Contains(conflicts[0], tc.conflict) || state.Covered {
					t.Fatalf("no floor applies, which enforce must report: %v", state.Conflicts)
				}
				if state.VersionFloor.Owner == VersionFloorOwnerDefenseClaw {
					t.Fatalf("floor state: %+v", state.VersionFloor)
				}
				verify, err := claudeTarget{}.Verify(opts)
				if err != nil || len(floorConflicts(verify)) != 1 || verify.Covered {
					t.Fatalf("verify: %v %v", err, verify.Conflicts)
				}

				report := opts
				report.ClaudeVersionFloor = config.ClaudeVersionFloorReport
				if state := reconcileClaude(t, report); len(floorConflicts(state)) != 0 {
					t.Fatalf("report only reports: %v", state.Conflicts)
				}
				requireUnrecordedFloorFile(t, opts, tc.content, "report")

				if _, err := (claudeTarget{}).RemoveOwned(opts); err != nil {
					t.Fatal(err)
				}
				requireUnrecordedFloorFile(t, opts, tc.content, "removal")

				// Once the administrator removes the file, the floor comes back.
				if err := os.Remove(claudeFloorFile(t, opts)); err != nil {
					t.Fatal(err)
				}
				reconcileClaude(t, opts)
				if readFile(t, claudeFloorFile(t, opts)) != wantClaudeFloorBytes {
					t.Fatal("the floor must return once the name is free")
				}
			})
		}
	})

	// A floor DefenseClaw wrote becomes the administrator's once someone changes
	// it: DefenseClaw drops its record and leaves the new bytes in every mode and
	// at removal.
	t.Run("a changed floor", func(t *testing.T) {
		withHigherSources(t)
		opts := testOptions(t)
		reconcileClaude(t, opts)
		if recorded, _ := ClaudeVersionFloorRecorded(opts); !recorded {
			t.Fatal("DefenseClaw must record the floor it writes")
		}
		edited := "{\n  \"requiredMinimumVersion\": \"2.1.200\"\n}\n"
		writeFile(t, claudeFloorFile(t, opts), edited)
		state := reconcileClaude(t, opts)
		requireUnrecordedFloorFile(t, opts, edited, "reconcile")
		if state.VersionFloor.Owner != VersionFloorOwnerAdministrator || len(floorConflicts(state)) != 0 || !hasDetail(state, "no longer holds DefenseClaw entries") {
			t.Fatalf("floor %+v conflicts %v details %v", state.VersionFloor, state.Conflicts, state.Details)
		}
		for _, mode := range []string{config.ClaudeVersionFloorReport, config.ClaudeVersionFloorOff, config.ClaudeVersionFloorEnforce} {
			opts.ClaudeVersionFloor = mode
			reconcileClaude(t, opts)
			requireUnrecordedFloorFile(t, opts, edited, "version_floor "+mode)
		}
		if _, err := (claudeTarget{}).RemoveOwned(opts); err != nil {
			t.Fatal(err)
		}
		requireUnrecordedFloorFile(t, opts, edited, "removal")
	})
}

func TestClaudeVersionFloorOnDarwinAndItsPlist(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	opts.GOOS = "darwin"
	reconcileClaude(t, opts)
	path := claudeFloorFile(t, opts)
	if !strings.HasSuffix(filepath.ToSlash(path), "/Library/Application Support/ClaudeCode/managed-settings.d/00-defenseclaw-version-floor.json") || readFile(t, path) != wantClaudeFloorBytes {
		t.Fatalf("darwin floor at %s", path)
	}
	plist := "/Library/Managed Preferences/com.anthropic.claudecode.plist"
	withHigherSources(t, higherSource(t, plist, `{"requiredMinimumVersion": "2.1.300"}`))
	state := reconcileClaude(t, opts)
	if fileExists(path) || state.VersionFloor.Owner != VersionFloorOwnerAdministrator || state.VersionFloor.Source != plist {
		t.Fatalf("a managed preferences value wins: %+v", state.VersionFloor)
	}
}

// Claude Code builds older than 2.1.242 read only a higher-precedence source
// (HKLM Settings, the managed preferences plist) and ignore the files, and
// every build the floor is meant to stop is older than that, with or without
// managedSourcesBehavior: merge. While such a source is in force without the
// key, no floor reaches those builds: verify fails (a warning under
// higher_precedence_sources: warn) even when that source embeds DefenseClaw's
// hooks.
func TestClaudeVersionFloorIsNotAppliedUnderAHigherPrecedenceSource(t *testing.T) {
	const source = `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`
	hooks, err := renderClaudeDropIn(testOptions(t), testOptions(t).PolicyFor("claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	withMerge := strings.Replace(string(hooks), "{", `{"managedSourcesBehavior": "merge",`, 1)
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "no merge", raw: `{"model": "opus"}`},
		{name: "embeds DefenseClaw's hooks", raw: string(hooks)},
		{name: "merge", raw: withMerge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOptions(t)
			withHigherSources(t, higherSource(t, source, tc.raw))
			reconcileClaude(t, opts)
			verify, err := claudeTarget{}.Verify(opts)
			if err != nil {
				t.Fatal(err)
			}
			if !hasConflict(verify, "outranks the managed settings files and does not set requiredMinimumVersion") || verify.VersionFloor.IgnoredBy != source {
				t.Fatalf("a higher-precedence source without the key must fail the floor: %v %+v", verify.Conflicts, verify.VersionFloor)
			}
			if !strings.Contains(verify.VersionFloor.Summary(), "not applied: "+source) {
				t.Fatalf("summary: %s", verify.VersionFloor.Summary())
			}
			if tc.name != "no merge" && hasConflict(verify, "does not include DefenseClaw's hooks") {
				t.Fatalf("the hooks are covered by that source: %v", verify.Conflicts)
			}

			warn := withPolicy(testOptions(t), "claudecode", func(p *config.EnterpriseConnectorPolicy) { p.HigherPrecedenceSources = "warn" })
			reconcileClaude(t, warn)
			verify, err = claudeTarget{}.Verify(warn)
			if err != nil || len(floorConflicts(verify)) != 0 || !hasDetail(verify, "outranks the managed settings files and does not set requiredMinimumVersion") {
				t.Fatalf("higher_precedence_sources: warn only warns: %v %v", err, verify.Conflicts)
			}
		})
	}

	// The key in that source is the administrator's floor.
	opts := testOptions(t)
	withHigherSources(t, higherSource(t, source, `{"requiredMinimumVersion": "2.1.200"}`))
	reconcileClaude(t, opts)
	if verify, err := (claudeTarget{}).Verify(opts); err != nil || len(floorConflicts(verify)) != 0 || verify.VersionFloor.IgnoredBy != "" || verify.VersionFloor.Owner != VersionFloorOwnerAdministrator {
		t.Fatalf("verify: %v %v %+v", err, verify.Conflicts, verify.VersionFloor)
	}
}

// The Windows pass runs inside the lifecycle's lock, only for the directory
// that lock guards, and takes no lock when there is nothing to do.
func TestClaudeVersionFloorLockedPass(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	// The linux-rooted tree joins with "/" (also on a Windows host).
	dir := path.Dir(claudeFloorFile(t, opts))
	calls := 0
	locked := func(fn func(string) error) error {
		calls++
		return fn(dir)
	}
	var state State
	if err := reconcileClaudeVersionFloorFor(opts, []string{"codex"}, locked, &state); err != nil || calls != 0 {
		t.Fatalf("nothing to write or remove must take no lock: calls=%d %v", calls, err)
	}
	if err := reconcileClaudeVersionFloorFor(opts, []string{"claudecode"}, locked, &state); err != nil || calls != 1 {
		t.Fatalf("publish: calls=%d %v", calls, err)
	}
	if readFile(t, claudeFloorFile(t, opts)) != wantClaudeFloorBytes {
		t.Fatal("the locked pass must write the floor")
	}
	if fileExists(filepath.Join(dir, DefenseClawDropInName)) {
		t.Fatal("the locked pass must never write the hook drop-in")
	}
	wrong := func(fn func(string) error) error { return fn(filepath.Join(dir, "elsewhere")) }
	if err := os.Remove(claudeFloorFile(t, opts)); err != nil {
		t.Fatal(err)
	}
	if err := reconcileClaudeVersionFloorFor(opts, []string{"claudecode"}, wrong, &state); err == nil || fileExists(claudeFloorFile(t, opts)) {
		t.Fatalf("a lock for another directory must be refused: %v", err)
	}
	reconcileClaudeVersionFloorFor(opts, []string{"claudecode"}, locked, &state)
	if err := reconcileClaudeVersionFloorFor(opts, []string{"codex"}, locked, &state); err != nil || fileExists(claudeFloorFile(t, opts)) {
		t.Fatalf("an inactive claudecode must withdraw the floor: %v", err)
	}
	reconcileClaudeVersionFloorFor(opts, []string{"claudecode"}, locked, &state)
	failing := func(func(string) error) error { return errors.New("lock timeout") }
	if err := removeClaudeVersionFloorWith(opts, failing, &state); err == nil || !fileExists(claudeFloorFile(t, opts)) {
		t.Fatalf("removal must run inside the lock: %v", err)
	}
	if err := removeClaudeVersionFloorWith(opts, locked, &state); err != nil || fileExists(claudeFloorFile(t, opts)) {
		t.Fatalf("locked removal: %v", err)
	}

	// The locked pass (the Windows guardian's) follows
	// connectors.claudecode.ownership: merge writes the floor, verify_only
	// neither writes nor removes it, and off removes DefenseClaw's floor.
	t.Run("ownership", func(t *testing.T) {
		withHigherSources(t)
		opts := testOptions(t)
		dir := path.Dir(claudeFloorFile(t, opts))
		locked := func(fn func(string) error) error { return fn(dir) }
		ownership := func(mode string) Options {
			return withPolicy(opts, "claudecode", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = mode })
		}
		var state State
		if err := reconcileClaudeVersionFloorFor(ownership(config.MachinePolicyOwnershipVerifyOnly), []string{"claudecode"}, locked, &state); err != nil || fileExists(claudeFloorFile(t, opts)) {
			t.Fatalf("verify_only must not write the floor: %v", err)
		}
		if err := reconcileClaudeVersionFloorFor(ownership(config.MachinePolicyOwnershipMerge), []string{"claudecode"}, locked, &state); err != nil || readFile(t, claudeFloorFile(t, opts)) != wantClaudeFloorBytes {
			t.Fatalf("merge must write the floor: %v", err)
		}
		if err := reconcileClaudeVersionFloorFor(ownership(config.MachinePolicyOwnershipVerifyOnly), []string{"claudecode"}, locked, &state); err != nil || readFile(t, claudeFloorFile(t, opts)) != wantClaudeFloorBytes {
			t.Fatalf("verify_only must not remove the floor: %v", err)
		}
		if err := reconcileClaudeVersionFloorFor(ownership(config.MachinePolicyOwnershipOff), []string{"claudecode"}, locked, &state); err != nil || fileExists(claudeFloorFile(t, opts)) {
			t.Fatalf("ownership off must remove DefenseClaw's floor: %v", err)
		}
		if recorded, _ := ClaudeVersionFloorRecorded(opts); recorded {
			t.Fatal("ownership off must remove the floor record")
		}
	})

	// The locked pass (Windows) takes no lock for a file it did not write: an
	// unrecorded floor file never needs removing.
	t.Run("unrecorded file", func(t *testing.T) {
		withHigherSources(t)
		opts := testOptions(t)
		dir := path.Dir(claudeFloorFile(t, opts))
		calls := 0
		locked := func(fn func(string) error) error {
			calls++
			return fn(dir)
		}
		writeFile(t, claudeFloorFile(t, opts), wantClaudeFloorBytes)
		var state State
		if err := reconcileClaudeVersionFloorFor(opts, []string{"codex"}, locked, &state); err != nil || calls != 0 {
			t.Fatalf("an inactive claudecode with only an administrator file takes no lock: calls=%d %v", calls, err)
		}
		if err := removeClaudeVersionFloorWith(opts, locked, &state); err != nil || calls != 0 {
			t.Fatalf("removal with nothing recorded takes no lock: calls=%d %v", calls, err)
		}
		if err := reconcileClaudeVersionFloorFor(opts, []string{"claudecode"}, locked, &state); err != nil || calls != 1 {
			t.Fatalf("publish: calls=%d %v", calls, err)
		}
		requireUnrecordedFloorFile(t, opts, wantClaudeFloorBytes, "the locked pass")
		// An uninstall with purge removes an unrecorded file that holds
		// exactly DefenseClaw's floor, and keeps any other.
		if removed, err := purgeUnrecordedClaudeVersionFloor(opts, locked); err != nil || !removed || fileExists(claudeFloorFile(t, opts)) {
			t.Fatalf("purge of DefenseClaw's unrecorded floor: removed=%v %v", removed, err)
		}
		writeFile(t, claudeFloorFile(t, opts), "{\"requiredMinimumVersion\": \"9.9.9\"}\n")
		if removed, err := purgeUnrecordedClaudeVersionFloor(opts, locked); err != nil || removed || !fileExists(claudeFloorFile(t, opts)) {
			t.Fatalf("purge must keep an administrator's floor file: removed=%v %v", removed, err)
		}
	})
}

func TestStandaloneOptionsCarryTheVersionFloorMode(t *testing.T) {
	layout, err := managed.StandaloneLayoutFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	opts, err := StandaloneOptions(layout, "", "", cfg)
	if err != nil || opts.ClaudeVersionFloor != config.ClaudeVersionFloorEnforce {
		t.Fatalf("default mode: %q %v", opts.ClaudeVersionFloor, err)
	}
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"claudecode": {VersionFloor: "Report"}}
	if opts, err = StandaloneOptions(layout, "", "", cfg); err != nil || opts.ClaudeVersionFloor != config.ClaudeVersionFloorReport {
		t.Fatalf("configured mode: %q %v", opts.ClaudeVersionFloor, err)
	}
	if policy := opts.PolicyFor("claudecode"); policy.Ownership != config.MachinePolicyOwnershipMerge {
		t.Fatalf("version_floor alone must leave the other claudecode keys at their defaults: %+v", policy)
	}
}

// Claude Code builds older than 2.1.242 read only a higher-precedence
// source (HKLM Settings, the managed preferences plist), and every build the
// floor is meant to stop is older. So under version_floor: enforce, the
// exports for those sources carry requiredMinimumVersion at the floor, and a
// fleet that deploys one of them passes verify without a hand edit. The
// managed-settings.d hook drop-in never carries the floor.
func TestClaudeHigherPrecedenceExportsCarryTheVersionFloor(t *testing.T) {
	wants := map[string]string{
		"claude-hklm-json":        `"requiredMinimumVersion":"2.1.154"`,
		"reg":                     `\"requiredMinimumVersion\":\"2.1.154\"`,
		"plist":                   "<key>requiredMinimumVersion</key>",
		"intune-settings-catalog": `\"requiredMinimumVersion\":\"2.1.154\"`,
	}
	for format, want := range wants {
		data, err := claudeTarget{}.Export(testOptions(t), format)
		if err != nil || !strings.Contains(string(data), want) {
			t.Fatalf("%s export under version_floor: enforce must carry %s: %v\n%s", format, want, err, data)
		}
		if format == "plist" && !strings.Contains(string(data), "<string>2.1.154</string>") {
			t.Fatalf("plist export must set the floor value:\n%s", data)
		}
		for _, mode := range []string{config.ClaudeVersionFloorReport, config.ClaudeVersionFloorOff} {
			opts := testOptions(t)
			opts.ClaudeVersionFloor = mode
			data, err := claudeTarget{}.Export(opts, format)
			if err != nil || strings.Contains(string(data), "requiredMinimumVersion") {
				t.Fatalf("%s export with version_floor: %s must not set the floor: %v", format, mode, err)
			}
		}
	}
	if hooks, err := (claudeTarget{}).Export(testOptions(t), "json"); err != nil || strings.Contains(string(hooks), "requiredMinimumVersion") {
		t.Fatalf("the managed-settings.d hook drop-in export must not carry the floor: %v", err)
	}

	const source = `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`
	opts := testOptions(t)
	exported, err := claudeTarget{}.Export(opts, "claude-hklm-json")
	if err != nil {
		t.Fatal(err)
	}
	withHigherSources(t, higherSource(t, source, string(exported)))
	reconcileClaude(t, opts)
	verify, err := claudeTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !verify.Covered || len(verify.Conflicts) != 0 || verify.VersionFloor.Owner != VersionFloorOwnerAdministrator || verify.VersionFloor.Value != "2.1.154" {
		t.Fatalf("an HKLM source deployed from DefenseClaw's export must pass verify: covered=%v %v %+v", verify.Covered, verify.Conflicts, verify.VersionFloor)
	}

	t.Run("export", func(t *testing.T) {
		opts := testOptions(t)
		data, err := claudeTarget{}.Export(opts, "version-floor")
		if err != nil || string(data) != wantClaudeFloorBytes {
			t.Fatalf("version-floor export: %v %q", err, data)
		}
		opts.ClaudeVersionFloor = config.ClaudeVersionFloorOff
		if _, err := (claudeTarget{}).Export(opts, "version-floor"); err == nil || !strings.Contains(err.Error(), "version_floor") {
			t.Fatalf("off must refuse the export, got %v", err)
		}
		hooks, err := claudeTarget{}.Export(testOptions(t), "json")
		if err != nil || strings.Contains(string(hooks), "requiredMinimumVersion") {
			t.Fatalf("the hook drop-in export must not carry the floor: %v", err)
		}
	})
}

// A crash, or a failed save, between replacing the floor drop-in (a release
// that raises the floor) and saving its ownership record leaves DefenseClaw's
// current rendering with a record that holds the previous postimage. The
// drop-in stays DefenseClaw's: verify reports it as DefenseClaw's, the next
// pass records it again and withdraws it when an administrator sets the key,
// and removal deletes it.
func TestClaudeVersionFloorSurvivesACrashBeforeItsRecordIsSaved(t *testing.T) {
	previous := sha256Hex([]byte("{\n  \"requiredMinimumVersion\": \"2.1.100\"\n}\n"))
	for _, next := range []string{"verify", "reconcile", "remove"} {
		t.Run(next, func(t *testing.T) {
			withHigherSources(t)
			opts := testOptions(t)
			reconcileClaude(t, opts)
			record, err := loadRecord(opts, claudeVersionFloorRecord)
			if err != nil || record == nil {
				t.Fatalf("floor record: %v %v", record, err)
			}
			record.PostimageSHA256 = previous
			if err := saveRecord(opts, record); err != nil {
				t.Fatal(err)
			}
			floorFile := claudeFloorFile(t, opts)
			switch next {
			case "verify":
				verify, err := claudeTarget{}.Verify(opts)
				if err != nil || verify.VersionFloor.Owner != VersionFloorOwnerDefenseClaw || len(floorConflicts(verify)) != 0 {
					t.Fatalf("verify must report DefenseClaw's floor: %v %v %+v", err, verify.Conflicts, verify.VersionFloor)
				}
			case "reconcile":
				state := reconcileClaude(t, opts)
				if state.VersionFloor.Owner != VersionFloorOwnerDefenseClaw || readFile(t, floorFile) != wantClaudeFloorBytes {
					t.Fatalf("reconcile must keep DefenseClaw's floor: %+v", state.VersionFloor)
				}
				if record, err := loadRecord(opts, claudeVersionFloorRecord); err != nil || record == nil || record.PostimageSHA256 != sha256Hex([]byte(wantClaudeFloorBytes)) {
					t.Fatalf("reconcile must record the floor again: %+v %v", record, err)
				}
				writeFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.json"), `{"requiredMinimumVersion": "2.1.200"}`)
				reconcileClaude(t, opts)
				if fileExists(floorFile) {
					t.Fatal("DefenseClaw's floor must be withdrawn once the administrator sets the key")
				}
			case "remove":
				if _, err := (claudeTarget{}).RemoveOwned(opts); err != nil {
					t.Fatal(err)
				}
				if fileExists(floorFile) {
					t.Fatal("removal must delete DefenseClaw's floor")
				}
			}
			if next != "verify" {
				if recorded, _ := ClaudeVersionFloorRecorded(opts); recorded != (next == "reconcile" && fileExists(floorFile)) {
					t.Fatalf("floor record after %s: %v", next, recorded)
				}
			}
		})
	}
}

// An administrator value set after install in a file that merges before
// DefenseClaw's floor drop-in (managed-settings.json, or a drop-in whose name
// sorts first) does not apply while the drop-in is there: verify reports the
// drop-in's value as the effective one and marks the connector as drift, so
// the lifecycle's ensure re-applies and withdraws the drop-in; then the
// administrator's value applies and verify passes.
func TestClaudeVersionFloorAdministratorValueAddedAfterInstall(t *testing.T) {
	for _, file := range []string{"managed-settings.json", "managed-settings.d/00-admin.json"} {
		t.Run(file, func(t *testing.T) {
			withHigherSources(t)
			opts := publishTestOptions(t)
			reconcileClaude(t, opts)
			source := path.Join(claudeDir(t, opts), file)
			writeFile(t, source, `{"requiredMinimumVersion": "2.1.200"}`)

			verify, err := claudeTarget{}.Verify(opts)
			if err != nil {
				t.Fatal(err)
			}
			floor := verify.VersionFloor
			if floor.Owner != VersionFloorOwnerDefenseClaw || floor.Value != "2.1.154" || floor.Overridden != "2.1.200" || floor.OverriddenSource != source {
				t.Fatalf("verify must report the drop-in's value as the one in force: %+v", floor)
			}
			if verify.Covered || !hasConflict(verify, "merges after it") {
				t.Fatalf("the overridden administrator value must fail verify: covered=%v %v", verify.Covered, verify.Conflicts)
			}
			if summary := floor.Summary(); !strings.Contains(summary, "replaces 2.1.200") || strings.Contains(summary, "not a version") {
				t.Fatalf("summary: %s", summary)
			}
			all, err := VerifyAll(opts, []string{"claudecode"})
			if err != nil || containsString(all.MachinePolicyConnectors, "claudecode") {
				t.Fatalf("a drifted connector is not reported in place, so ensure re-applies: %v %v", all.MachinePolicyConnectors, err)
			}

			// ensure re-applies the machine policy.
			if _, err := Publish(opts, []string{"claudecode"}); err != nil {
				t.Fatal(err)
			}
			if fileExists(claudeFloorFile(t, opts)) {
				t.Fatal("re-applying must withdraw DefenseClaw's drop-in")
			}
			verify, err = claudeTarget{}.Verify(opts)
			if err != nil || !verify.Covered || verify.VersionFloor.Owner != VersionFloorOwnerAdministrator || verify.VersionFloor.Value != "2.1.200" {
				t.Fatalf("after ensure the administrator's value applies and verify passes: %v %v %+v", err, verify.Conflicts, verify.VersionFloor)
			}
			if all, err := VerifyAll(opts, []string{"claudecode"}); err != nil || !containsString(all.MachinePolicyConnectors, "claudecode") {
				t.Fatalf("after ensure the connector is in place: %v %v", all.MachinePolicyConnectors, err)
			}
		})
	}
}

// GAP-1555: a machine-wide hook drop-in rendered from a newer hook contract
// (standalone Windows renders it from the oldest enrolled one) raises the
// floor to that contract's lowest version, and the report says why; back on
// the oldest contract the floor returns to the lowest verified version.
func TestClaudeVersionFloorFollowsTheMachineHookContract(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	opts.ClaudeMachineHookContract = "claudecode-hooks-v2"

	state := reconcileClaude(t, opts)
	mustNoConflicts(t, state)
	if got, want := readFile(t, claudeFloorFile(t, opts)), "{\n  \"requiredMinimumVersion\": \"2.1.219\"\n}\n"; got != want {
		t.Fatalf("floor drop-in = %q, want %q", got, want)
	}
	floor := state.VersionFloor
	if floor == nil || floor.Floor != "2.1.219" || floor.Value != "2.1.219" || !strings.Contains(floor.Reason, "claudecode-hooks-v2") {
		t.Fatalf("floor state: %+v", floor)
	}
	if !strings.Contains(floor.Summary(), "claudecode-hooks-v2") || !hasDetail(state, "2.1.219, not 2.1.154") {
		t.Fatalf("status must name why the floor is 2.1.219: %s / %v", floor.Summary(), state.Details)
	}
	// GAP-1555: builds before 2.1.163 ignore the floor and still show the
	// unknown-event warning; status and verify must say so.
	if !hasDetail(state, "builds before 2.1.163 ignore the version floor") {
		t.Fatalf("status must name the pre-2.1.163 residual: %v", state.Details)
	}
	if again := reconcileClaude(t, opts); again.Changed {
		t.Fatalf("a second reconcile must be a no-op: %+v", again)
	}

	opts.ClaudeMachineHookContract = "claudecode-hooks-v1"
	state = reconcileClaude(t, opts)
	mustNoConflicts(t, state)
	if got := readFile(t, claudeFloorFile(t, opts)); got != wantClaudeFloorBytes {
		t.Fatalf("floor drop-in on the v1 contract = %q, want %q", got, wantClaudeFloorBytes)
	}
	if state.VersionFloor == nil || state.VersionFloor.Reason != "" {
		t.Fatalf("no reason on the lowest contract: %+v", state.VersionFloor)
	}
}
