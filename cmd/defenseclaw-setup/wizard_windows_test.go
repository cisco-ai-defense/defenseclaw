// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedUserPathRoundTripPreservesExactSeparators(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	for _, before := range []string{
		"",
		`C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps`,
		`C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps;`,
		`C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps;;`,
	} {
		installed, reusedSeparator := appendUserPathEntry(before, commandDir)
		got := removeUserPathEntry(installed, commandDir, reusedSeparator)
		if got != before {
			t.Fatalf("PATH round trip for %q = %q, want exact original", before, got)
		}
	}
}

func TestOwnedUserPathRemovalPreservesLaterEntries(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	before := `C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps;`
	installed, reusedSeparator := appendUserPathEntry(before, commandDir)
	current := installed + `;C:\Users\runneradmin\bin`
	want := `C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps;C:\Users\runneradmin\bin`
	if got := removeUserPathEntry(current, commandDir, reusedSeparator); got != want {
		t.Fatalf("PATH removal after a later user edit = %q, want %q", got, want)
	}
}

func TestUpdateInstalledPathOwnershipRecordsReusedSeparator(t *testing.T) {
	installRoot := t.TempDir()
	installerDir := filepath.Join(installRoot, "installer")
	if err := os.MkdirAll(installerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(installerDir, "install-state.json")
	if err := writeJSON(statePath, installState{}); err != nil {
		t.Fatal(err)
	}
	if err := updateInstalledPathOwnership(installRoot, true, true); err != nil {
		t.Fatal(err)
	}
	var state installState
	if err := readJSON(statePath, &state); err != nil {
		t.Fatal(err)
	}
	if !state.PathEntryOwned || !state.PathSeparatorReused {
		t.Fatalf("updated PATH ownership = owned:%t reused:%t", state.PathEntryOwned, state.PathSeparatorReused)
	}
}

func TestWizardChoiceMappings(t *testing.T) {
	connectors := []wizardChoice{
		{Label: "Configure later", Value: "none"},
		{Label: "Codex CLI", Value: "codex"},
		{Label: "Claude Code", Value: "claudecode"},
	}
	modes := []wizardChoice{
		{Label: "Observe", Value: "observe"},
		{Label: "Action", Value: "action"},
	}
	if len(wizardConnectorChoices) != len(connectors) {
		t.Fatalf("connector choice count = %d, want %d", len(wizardConnectorChoices), len(connectors))
	}
	for index, want := range connectors {
		if got := wizardConnectorChoices[index]; got != want {
			t.Fatalf("connector choice %d = %+v, want %+v", index, got, want)
		}
		if got := connectorIndex(want.Value); got != index {
			t.Fatalf("connectorIndex(%q) = %d, want %d", want.Value, got, index)
		}
		if got := connectorValue(index); got != want.Value {
			t.Fatalf("connectorValue(%d) = %q, want %q", index, got, want.Value)
		}
	}
	if len(wizardModeChoices) != len(modes) {
		t.Fatalf("mode choice count = %d, want %d", len(wizardModeChoices), len(modes))
	}
	for index, want := range modes {
		if got := wizardModeChoices[index]; got != want {
			t.Fatalf("mode choice %d = %+v, want %+v", index, got, want)
		}
		if got := modeIndex(want.Value); got != index {
			t.Fatalf("modeIndex(%q) = %d, want %d", want.Value, got, index)
		}
		if got := modeValue(index); got != want.Value {
			t.Fatalf("modeValue(%d) = %q, want %q", index, got, want.Value)
		}
	}
	if connectorIndex("invalid") != 0 || connectorValue(-1) != "none" || connectorValue(99) != "none" {
		t.Fatal("invalid connector selections did not fall back to Configure later")
	}
	if modeIndex("invalid") != 0 || modeValue(-1) != "observe" || modeValue(99) != "observe" {
		t.Fatal("invalid mode selections did not fall back to Observe")
	}
}

func TestOptionsFromWizardSelectionsMatrix(t *testing.T) {
	for connectorSelection, connector := range []string{"none", "codex", "claudecode"} {
		for modeSelection, mode := range []string{"observe", "action"} {
			for _, startGateway := range []bool{false, true} {
				name := connector + "/" + mode
				if startGateway {
					name += "/start"
				} else {
					name += "/stopped"
				}
				t.Run(name, func(t *testing.T) {
					opts := optionsFromWizardSelections(
						options{Action: "install"},
						connectorSelection,
						modeSelection,
						startGateway,
					)
					if opts.Action != "install" || !opts.Quiet {
						t.Fatalf("wizard options lost action/quiet state: %+v", opts)
					}
					if opts.Connector != connector || opts.Mode != mode || opts.StartGateway != startGateway {
						t.Fatalf("wizard options mapped incorrectly: %+v", opts)
					}
					if !opts.ConnectorSet || !opts.ModeSet || !opts.StartGatewaySet {
						t.Fatalf("wizard options omitted explicit property markers: %+v", opts)
					}
				})
			}
		}
	}
}
