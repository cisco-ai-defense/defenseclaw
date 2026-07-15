// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func TestOwnedUserPathRoundTripPreservesExactSeparators(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	for _, before := range []string{
		"",
		`C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps`,
		`;C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps`,
		`;;C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps`,
	} {
		installed, reusedSeparator := prependUserPathEntry(before, commandDir)
		got := removeUserPathEntry(installed, commandDir, reusedSeparator)
		if got != before {
			t.Fatalf("PATH round trip for %q = %q, want exact original", before, got)
		}
	}
}

func TestOwnedUserPathRemovalPreservesLaterEntries(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	before := `C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps`
	installed, reusedSeparator := prependUserPathEntry(before, commandDir)
	current := installed + `;C:\Users\runneradmin\bin`
	want := `C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps;C:\Users\runneradmin\bin`
	if got := removeUserPathEntry(current, commandDir, reusedSeparator); got != want {
		t.Fatalf("PATH removal after a later user edit = %q, want %q", got, want)
	}
}

func TestOwnedUserPathRemovalRefusesAmbiguousEndpointDuplicates(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	other := `C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps`
	current := commandDir + ";" + other + ";" + commandDir

	got, err := removeOwnedUserPathEntry(current, commandDir, false)
	if err == nil {
		t.Fatal("ambiguous managed PATH endpoints were removed without an ownership proof")
	}
	if got != current {
		t.Fatalf("PATH changed on ambiguous removal: %q", got)
	}
}

func TestOwnedUserPathRemovalKeepsKelvinSignPathDistinct(t *testing.T) {
	owned := filepath.Join(t.TempDir(), "missing-K", "bin")
	foreign := strings.Replace(owned, "missing-K", "missing-K", 1)
	if !strings.EqualFold(owned, foreign) {
		t.Fatal("test precondition: Go EqualFold should conflate K and Kelvin sign")
	}
	current := owned + ";" + foreign
	got, err := removeOwnedUserPathEntry(current, owned, false)
	if err != nil {
		t.Fatalf("remove owned ordinal path: %v", err)
	}
	if got != foreign {
		t.Fatalf("PATH after removal = %q, want distinct foreign entry %q", got, foreign)
	}
	if pathContains([]string{foreign}, owned) {
		t.Fatal("PATH ownership comparison conflated ASCII K and Kelvin sign")
	}
	if !samePathEntry(owned+`\`, owned) {
		t.Fatal("PATH ownership comparison did not preserve filepath.Clean trailing-separator semantics")
	}
}

func TestOwnedUserPathRemovalRefusesReorderedEntry(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	current := `C:\Users\runneradmin\bin;` + commandDir

	got, err := removeOwnedUserPathEntry(current, commandDir, false)
	if err == nil {
		t.Fatal("reordered managed PATH entry was removed without an ownership proof")
	}
	if got != current {
		t.Fatalf("PATH changed on refused removal: %q", got)
	}
}

func TestOwnedUserPathRemovalRetryAcceptsOnlyAnAlreadyAbsentEntry(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	current := `C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps`

	got, err := removeOwnedUserPathEntry(current, commandDir, false)
	if err != nil || got != current {
		t.Fatalf("already-removed PATH retry = %q, %v", got, err)
	}

	reordered := current + ";" + commandDir + `;C:\Users\runneradmin\bin`
	got, err = removeOwnedUserPathEntry(reordered, commandDir, false)
	if err == nil || got != reordered {
		t.Fatalf("reordered PATH retry = %q, %v", got, err)
	}
}

func TestOwnedUserPathRemovalPlanDeletesOnlySetupCreatedEmptyValue(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	later := `C:\Users\runneradmin\bin`
	tests := []struct {
		name         string
		current      string
		valueCreated bool
		want         string
		wantDelete   bool
		wantErr      bool
	}{
		{name: "setup-created value", current: commandDir, valueCreated: true, wantDelete: true},
		{name: "pre-existing empty value", current: commandDir, valueCreated: false},
		{
			name:         "later user entry",
			current:      commandDir + ";" + later,
			valueCreated: true,
			want:         later,
		},
		{
			name:         "later duplicate",
			current:      commandDir + ";" + commandDir,
			valueCreated: true,
			want:         commandDir + ";" + commandDir,
			wantErr:      true,
		},
		{
			name:         "later empty entry",
			current:      commandDir + ";",
			valueCreated: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, deleteValue, err := planOwnedUserPathRemoval(test.current, commandDir, false, test.valueCreated)
			if (err != nil) != test.wantErr {
				t.Fatalf("removal error = %v, want error %t", err, test.wantErr)
			}
			if got != test.want || deleteValue != test.wantDelete {
				t.Fatalf("removal plan = value %q delete:%t, want value %q delete:%t", got, deleteValue, test.want, test.wantDelete)
			}
		})
	}
}

func TestOwnedUserPathRegistryRemovalRestoresValueExistence(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	later := `C:\Users\runneradmin\bin`
	tests := []struct {
		name         string
		current      string
		valueCreated bool
		expand       bool
		wantExists   bool
		want         string
	}{
		{name: "setup-created value", current: commandDir, valueCreated: true},
		{name: "pre-existing empty value", current: commandDir, wantExists: true},
		{
			name:         "user-changed value type",
			current:      commandDir,
			valueCreated: true,
			expand:       true,
			wantExists:   true,
		},
		{
			name:         "setup-created value with later entry",
			current:      commandDir + ";" + later,
			valueCreated: true,
			wantExists:   true,
			want:         later,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyPath := fmt.Sprintf(
				`Software\DefenseClawSetupTests\path-%d-%d`,
				os.Getpid(),
				time.Now().UnixNano(),
			)
			key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = key.Close()
				_ = registry.DeleteKey(registry.CURRENT_USER, keyPath)
			})
			setValue := key.SetStringValue
			if test.expand {
				setValue = key.SetExpandStringValue
			}
			if err := setValue("Path", test.current); err != nil {
				t.Fatal(err)
			}
			if _, err := mutateRegistryUserPath(
				registry.CURRENT_USER,
				keyPath,
				removeUserPathMutation(commandDir, false, test.valueCreated),
			); err != nil {
				t.Fatal(err)
			}
			got, gotType, err := key.GetStringValue("Path")
			if !test.wantExists {
				if err != registry.ErrNotExist {
					t.Fatalf("Path still exists as %q: %v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("Path = %q, want %q", got, test.want)
			}
			wantType := uint32(registry.SZ)
			if test.expand {
				wantType = registry.EXPAND_SZ
			}
			if gotType != wantType {
				t.Fatalf("Path registry type = %d, want %d", gotType, wantType)
			}
		})
	}
}

func TestOwnedUserPathRegistryRemovalRetriesAfterLaterFailures(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	later := `C:\Users\runneradmin\bin`
	keyPath := fmt.Sprintf(
		`Software\DefenseClawSetupTests\path-retry-%d-%d`,
		os.Getpid(),
		time.Now().UnixNano(),
	)
	key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = key.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, keyPath)
	})
	if err := key.SetStringValue("Path", commandDir+";"+later); err != nil {
		t.Fatal(err)
	}

	// The first mutation can be durable even when the subsequent desktop
	// broadcast fails. A committed retry must accept the already-absent entry.
	removeOwned := func() error {
		_, mutationErr := mutateRegistryUserPath(
			registry.CURRENT_USER,
			keyPath,
			removeUserPathMutation(commandDir, false, false),
		)
		return mutationErr
	}
	if err := removeOwned(); err != nil {
		t.Fatal(err)
	}
	if err := removeOwned(); err != nil {
		t.Fatalf("retry after post-mutation broadcast failure: %v", err)
	}
	// If Apps & Features removal then fails, the next committed retry reaches
	// PATH removal once more and must remain idempotent.
	if err := removeOwned(); err != nil {
		t.Fatalf("retry after later Apps & Features failure: %v", err)
	}
	got, _, err := key.GetStringValue("Path")
	if err != nil || got != later {
		t.Fatalf("PATH after committed retries = %q, %v; want %q", got, err, later)
	}
}

func TestLegacyAppendedUserPathRemovalPreservesTrailingSeparator(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	before := `C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps;`
	legacyInstalled := before + commandDir

	if got := removeUserPathEntry(legacyInstalled, commandDir, true); got != before {
		t.Fatalf("legacy PATH round trip = %q, want %q", got, before)
	}
}

func TestManagedUserPathPrecedesLegacyDefenseClawBin(t *testing.T) {
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	legacyDir := `C:\Users\runneradmin\.local\bin`
	before := legacyDir + `;C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps`

	installed, reusedSeparator := prependUserPathEntry(before, commandDir)
	entries := strings.Split(installed, ";")
	if len(entries) == 0 || !samePathEntry(entries[0], commandDir) {
		t.Fatalf("managed PATH entry did not win precedence: %q", installed)
	}
	if got := removeUserPathEntry(installed, commandDir, reusedSeparator); got != before {
		t.Fatalf("PATH round trip = %q, want %q", got, before)
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
	if err := updateInstalledPathOwnership(installRoot, true, true, false); err != nil {
		t.Fatal(err)
	}
	var state installState
	if err := readJSON(statePath, &state); err != nil {
		t.Fatal(err)
	}
	if !state.PathEntryOwned || !state.PathSeparatorReused || state.PathValueCreated {
		t.Fatalf(
			"updated PATH ownership = owned:%t reused:%t value-created:%t",
			state.PathEntryOwned,
			state.PathSeparatorReused,
			state.PathValueCreated,
		)
	}
}

func TestUpdateInstalledPathOwnershipRecordsCreatedValue(t *testing.T) {
	installRoot := t.TempDir()
	installerDir := filepath.Join(installRoot, "installer")
	if err := os.MkdirAll(installerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(installerDir, "install-state.json")
	if err := writeJSON(statePath, installState{}); err != nil {
		t.Fatal(err)
	}
	if err := updateInstalledPathOwnership(installRoot, true, false, true); err != nil {
		t.Fatal(err)
	}
	var state installState
	if err := readJSON(statePath, &state); err != nil {
		t.Fatal(err)
	}
	if !state.PathEntryOwned || state.PathSeparatorReused || !state.PathValueCreated {
		t.Fatalf(
			"updated PATH ownership = owned:%t reused:%t value-created:%t",
			state.PathEntryOwned,
			state.PathSeparatorReused,
			state.PathValueCreated,
		)
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
					wantGateway := startGateway || connector != "none"
					if opts.Connector != connector || opts.Mode != mode || opts.StartGateway != wantGateway {
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

func TestInteractiveInstallDefaultsPreserveExistingSelections(t *testing.T) {
	state := &installState{Connector: "claudecode", Mode: "action"}
	opts := applyInteractiveInstallDefaults(options{Action: "install"}, state, true, true)
	if opts.Connector != "claudecode" || opts.Mode != "action" || !opts.StartGateway {
		t.Fatalf("existing interactive defaults were not preserved: %+v", opts)
	}
	if opts.ConnectorSet || opts.ModeSet || opts.StartGatewaySet {
		t.Fatalf("defaults were incorrectly marked as explicit arguments: %+v", opts)
	}
}

func TestInteractiveInstallDefaultsRespectExplicitSelections(t *testing.T) {
	state := &installState{Connector: "claudecode", Mode: "action"}
	opts := applyInteractiveInstallDefaults(options{
		Action:          "install",
		Connector:       "none",
		Mode:            "observe",
		StartGateway:    false,
		ConnectorSet:    true,
		ModeSet:         true,
		StartGatewaySet: true,
	}, state, true, true)
	if opts.Connector != "none" || opts.Mode != "observe" || opts.StartGateway {
		t.Fatalf("explicit interactive arguments were overwritten: %+v", opts)
	}
}

func TestInteractiveInstallDefaultsRestoreRequiredGateway(t *testing.T) {
	state := &installState{Connector: "codex", Mode: "observe"}
	opts := applyInteractiveInstallDefaults(options{Action: "install"}, state, false, true)
	if !opts.StartGateway {
		t.Fatalf("configured connector did not restore the required gateway: %+v", opts)
	}
}

func TestInteractiveInstallDefaultsPreserveCLIOnlyOptOut(t *testing.T) {
	state := &installState{Connector: "none", Mode: "observe"}
	opts := applyInteractiveInstallDefaults(options{Action: "install"}, state, false, true)
	if opts.StartGateway {
		t.Fatalf("existing CLI-only autostart opt-out was lost: %+v", opts)
	}
	fresh := applyInteractiveInstallDefaults(options{Action: "install"}, nil, false, false)
	if !fresh.StartGateway {
		t.Fatalf("fresh interactive install did not retain the checked default: %+v", fresh)
	}
}

func TestWizardCompletionDescriptionMatchesConfiguredConnector(t *testing.T) {
	for _, tc := range []struct {
		connector string
		want      string
		reject    string
	}{
		{connector: "codex", want: "trusted automatically", reject: "open /hooks"},
		{connector: "claudecode", want: "Claude Code is configured", reject: "defenseclaw init"},
		{connector: "none", want: "defenseclaw init", reject: "open /hooks"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			got := wizardCompletionDescription(tc.connector)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("completion text %q does not contain %q", got, tc.want)
			}
			if strings.Contains(got, tc.reject) {
				t.Fatalf("completion text %q unexpectedly contains %q", got, tc.reject)
			}
		})
	}
}

func TestHighWord(t *testing.T) {
	if got := highWord(0x12345678); got != 0x1234 {
		t.Fatalf("highWord = %#x, want %#x", got, 0x1234)
	}
}

func TestWizardCompletionMessageUsesPrivateApplicationRange(t *testing.T) {
	if wmDone < wmApp || wmDone == dmGetDefID || wmDone == dmSetDefID {
		t.Fatalf("wmDone=%#x overlaps dialog-manager messages", wmDone)
	}
	if idPrimary != 1 || idCancel != 2 {
		t.Fatalf("standard dialog command IDs changed: primary=%d cancel=%d", idPrimary, idCancel)
	}
}

func TestWizardReportsCancellationOnlyAfterSuccessfulRollback(t *testing.T) {
	cancelled := errors.Join(errSetupCancelled, context.Canceled)
	if !wizardCancellationCompleted(userExitCode, cancelled) {
		t.Fatal("completed cancellation was not recognized")
	}
	if wizardCancellationCompleted(retryRequiredCode, errors.Join(cancelled, errors.New("rollback remains pending"))) {
		t.Fatal("pending rollback was reported as a completed cancellation")
	}
	if wizardCancellationCompleted(userExitCode, errors.New("unrelated failure")) {
		t.Fatal("unrelated failure was reported as a completed cancellation")
	}
}

func TestWizardCancellationConfirmationRechecksCompletedOperation(t *testing.T) {
	cancelCalls := 0
	wizard := setupWizard{
		running: true,
		operationCancel: func() {
			cancelCalls++
		},
	}
	wizard.requestCancellationWithPrompt(func() bool {
		// MessageBoxW pumps window messages; model wmDone clearing the operation
		// before the user confirms cancellation.
		wizard.running = false
		wizard.operationCancel = nil
		return true
	})
	if wizard.cancelRequested {
		t.Fatal("completed operation was changed to cancelling after confirmation closed")
	}
	if cancelCalls != 0 {
		t.Fatalf("completed operation cancel calls = %d, want 0", cancelCalls)
	}
}

func TestWizardFailureDescriptionIncludesRecoveryAndPrivateLog(t *testing.T) {
	detail := wizardFailureDescription(
		retryRequiredCode,
		errors.New("files are locked"),
		`C:\Users\tester\AppData\Local\DefenseClaw\InstallerState\setup.log`,
		nil,
	)
	for _, want := range []string{"Exit code: 1603", "durable setup journal", "files are locked", "run Setup again", "setup.log"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("failure detail %q does not contain %q", detail, want)
		}
	}
}

func TestWizardFailureDescriptionDistinguishesConnectorResidue(t *testing.T) {
	detail := wizardFailureDescription(
		retryRequiredCode,
		errors.New("DefenseClaw core installation completed, but connector reconciliation remains pending"),
		"",
		errors.New("log unavailable"),
	)
	for _, want := range []string{"core product transaction completed", "connector reconciliation", "log unavailable"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("connector residue detail %q does not contain %q", detail, want)
		}
	}
}

func TestTerminalPowerShellParamsRunsExactInstalledLauncher(t *testing.T) {
	launcher := `C:\Users\O'Brien\AppData\Local\Programs\DefenseClaw\bin\defenseclaw.exe`
	params := terminalPowerShellParams(launcher)
	if !strings.Contains(params, `O''Brien`) || !strings.Contains(params, "& '") {
		t.Fatalf("PowerShell parameters do not safely invoke the exact launcher: %q", params)
	}
	if strings.Contains(params, "defenseclaw init") {
		t.Fatalf("terminal launch unexpectedly starts initialization: %q", params)
	}
}
