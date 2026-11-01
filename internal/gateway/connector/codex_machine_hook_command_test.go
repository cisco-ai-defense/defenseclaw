// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// The machine command awaits the GUI-subsystem launcher on the handle
// Process.Start returns and exits with its exit code, so a fail-closed exit 2
// reaches Codex; the call-operator form with a stale $LASTEXITCODE is gone.
func TestWindowsCodexManagedHookCommandAwaitsLauncherExitCode(t *testing.T) {
	hookBinary := `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`
	decoded := decodePowerShellEncodedCommandForTest(t, windowsCodexManagedHookCommand(hookBinary))
	for _, want := range []string{
		"$ErrorActionPreference='Stop'",
		"$env:NoDefaultCurrentDirectoryInExePath='1'",
		"$hookStart=[System.Diagnostics.ProcessStartInfo]::new('" + hookBinary + "','hook --connector codex --enterprise-managed')",
		"$hookStart.UseShellExecute=$false",
		"$hookStart.RedirectStandardError=$true",
		"$hookProcess=[System.Diagnostics.Process]::Start($hookStart)",
		"$hookProcess.WaitForExit()",
		"exit $hookProcess.ExitCode",
	} {
		if !strings.Contains(decoded, want) {
			t.Fatalf("machine command lacks %q:\n%s", want, decoded)
		}
	}
	// stdout is never redirected: the launcher writes Codex's JSON decision
	// straight to the agent's stdout handle.
	if strings.Contains(decoded, "RedirectStandardOutput") {
		t.Fatalf("machine command captures the launcher's stdout:\n%s", decoded)
	}
	// Outside Constrained Language mode the script must not end on the call
	// operator's stale $LASTEXITCODE.
	fullLanguage := decoded[strings.Index(decoded, "$hookStart="):]
	if strings.Contains(fullLanguage, "$LASTEXITCODE") {
		t.Fatalf("machine command still depends on $LASTEXITCODE:\n%s", decoded)
	}
	if windowsCodexManagedHookCommand(hookBinary) == legacyCallOperatorWindowsCodexManagedHookCommand(hookBinary) {
		t.Fatal("current machine command equals the legacy call-operator form")
	}
}

// requirements.toml written by an earlier release carries the call-operator
// command. Reconcile replaces it in place (no duplicate, nothing refused),
// keeps administrator groups, and the result verifies.
func TestReconcileWindowsCodexRequirementsMigratesLegacyCallOperatorCommand(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	legacy := legacyWindowsCodexRequirementsForTest(t, opts)

	contains, err := windowsCodexRequirementsContainExactManagedHook(legacy, opts)
	if err != nil || !contains {
		t.Fatalf("legacy groups not recognized as DefenseClaw-owned: contains=%v err=%v", contains, err)
	}
	if err := verifyWindowsCodexRequirementsBytes(legacy, opts); err == nil {
		t.Fatal("legacy requirements verified; the call-operator command must be migrated")
	}

	rendered, changed, err := reconcileWindowsCodexRequirements(legacy, opts)
	if err != nil {
		t.Fatalf("reconcile legacy requirements: %v", err)
	}
	if !changed {
		t.Fatal("reconcile left the legacy command in place")
	}
	if err := verifyWindowsCodexRequirementsBytes(rendered, opts); err != nil {
		t.Fatalf("migrated requirements do not verify: %v", err)
	}
	if strings.Contains(string(rendered), legacyCallOperatorWindowsCodexManagedHookCommand(opts.HookBinary)) {
		t.Fatal("legacy command survived reconcile")
	}
	cfg, err := parseWindowsCodexRequirements(rendered)
	if err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	first := codexHookGroups[0]
	groups := hooks[first.eventType].([]interface{})
	if len(groups) != 2 {
		t.Fatalf("hooks.%s groups = %d, want the migrated group and the administrator group", first.eventType, len(groups))
	}
	if !windowsCodexMachineGroupMatches(groups[0], first, opts.HookBinary) {
		t.Fatalf("migrated group did not keep its position: %#v", groups)
	}
	again, changedAgain, err := reconcileWindowsCodexRequirements(rendered, opts)
	if err != nil || changedAgain || string(again) != string(rendered) {
		t.Fatalf("second reconcile not idempotent: changed=%v err=%v", changedAgain, err)
	}
}

// Removal takes a legacy group as DefenseClaw-owned, so an uninstall that
// runs before any reconcile migrated it does not strand the old command.
func TestRemoveWindowsCodexRequirementsOwnedChangesTakesLegacyCommand(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	legacy := legacyWindowsCodexRequirementsForTest(t, opts)
	cleaned, changed, err := removeWindowsCodexRequirementsOwnedChanges(legacy, []byte("administrator_key = \"preserve\"\n"), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("legacy DefenseClaw groups were not removed")
	}
	contains, err := windowsCodexRequirementsContainExactManagedHook(cleaned, opts)
	if err != nil || contains {
		t.Fatalf("legacy DefenseClaw groups survived removal: contains=%v err=%v", contains, err)
	}
}

// legacyWindowsCodexRequirementsForTest renders current requirements, then
// rewrites every DefenseClaw handler to the legacy call-operator command and
// appends an administrator group to the first event.
func legacyWindowsCodexRequirementsForTest(t *testing.T, opts WindowsCodexMachineRequirementsOptions) []byte {
	t.Helper()
	current, _, err := reconcileWindowsCodexRequirements([]byte("administrator_key = \"preserve\"\n"), opts)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseWindowsCodexRequirements(current)
	if err != nil {
		t.Fatal(err)
	}
	legacyCommand := legacyCallOperatorWindowsCodexManagedHookCommand(opts.HookBinary)
	hooks := cfg["hooks"].(map[string]interface{})
	for _, expected := range codexHookGroups {
		for _, raw := range hooks[expected.eventType].([]interface{}) {
			handler := raw.(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
			handler["command"] = legacyCommand
			handler["command_windows"] = legacyCommand
		}
	}
	first := codexHookGroups[0].eventType
	hooks[first] = append(hooks[first].([]interface{}), map[string]interface{}{
		"matcher": "administrator-owned",
		"hooks": []interface{}{map[string]interface{}{
			"type":            "command",
			"command":         `C:\AdministratorHooks\audit.exe`,
			"command_windows": `C:\AdministratorHooks\audit.exe`,
			"timeout":         int64(9),
		}},
	})
	legacy, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return legacy
}
