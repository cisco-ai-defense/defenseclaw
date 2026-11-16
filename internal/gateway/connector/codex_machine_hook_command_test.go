// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// The unbound machine command (the 26.8.4 Secure Client form) awaits the
// GUI-subsystem launcher on the handle Process.Start returns and exits with
// its exit code, so a fail-closed exit 2 reaches Codex; the call-operator
// form with a stale $LASTEXITCODE is only recognized, never rendered.
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
	for _, command := range []string{
		windowsCodexManagedHookCommand(hookBinary),
		legacyCallOperatorWindowsCodexManagedHookCommand(hookBinary),
	} {
		if event, contract, ok := windowsCodexRenderedHookCommand(command, hookBinary); !ok || event != "" || contract != "" {
			t.Fatalf("unbound command not owned: event=%q contract=%q ok=%v", event, contract, ok)
		}
	}
}

// requirements.toml written by a 26.8.x Secure Client release carries an
// unbound command (the call-operator form, or the awaited form of 26.8.4).
// Reconcile replaces it with the bound group (no duplicate, nothing
// refused), keeps administrator groups, and the result verifies.
func TestReconcileWindowsCodexRequirementsMigratesUnboundCommands(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	contracts := KnownHookContracts("codex")
	opts.HookContractID = contracts[len(contracts)-1].ContractID
	for name, legacyCommand := range map[string]string{
		"call operator": legacyCallOperatorWindowsCodexManagedHookCommand(opts.HookBinary),
		"awaited":       windowsCodexManagedHookCommand(opts.HookBinary),
	} {
		t.Run(name, func(t *testing.T) {
			legacy := unboundWindowsCodexRequirementsForTest(t, opts, legacyCommand)
			if err := verifyWindowsCodexRequirementsBytes(legacy, opts); err == nil {
				t.Fatal("unbound requirements verified; the unbound command must be migrated")
			}
			rendered, changed, err := reconcileWindowsCodexRequirements(legacy, opts, true)
			if err != nil {
				t.Fatalf("reconcile unbound requirements: %v", err)
			}
			if !changed {
				t.Fatal("reconcile left the unbound command in place")
			}
			if err := verifyWindowsCodexRequirementsBytes(rendered, opts); err != nil {
				t.Fatalf("migrated requirements do not verify: %v", err)
			}
			if strings.Contains(string(rendered), legacyCommand) {
				t.Fatal("unbound command survived reconcile")
			}
			cfg, err := parseWindowsCodexRequirements(rendered)
			if err != nil {
				t.Fatal(err)
			}
			hooks := cfg["hooks"].(map[string]interface{})
			first := windowsCodexMachineProfileGroups(opts)[0]
			groups := hooks[first.eventType].([]interface{})
			if len(groups) != 2 {
				t.Fatalf("hooks.%s groups = %d, want the migrated group and the administrator group", first.eventType, len(groups))
			}
			exact := 0
			for _, group := range groups {
				if windowsCodexMachineGroupMatches(group, first, opts) {
					exact++
				}
			}
			if exact != 1 {
				t.Fatalf("hooks.%s exact DefenseClaw groups = %d, want 1: %#v", first.eventType, exact, groups)
			}
			again, changedAgain, err := reconcileWindowsCodexRequirements(rendered, opts, true)
			if err != nil || changedAgain || string(again) != string(rendered) {
				t.Fatalf("second reconcile not idempotent: changed=%v err=%v", changedAgain, err)
			}
		})
	}
}

// Removal takes an unbound group as DefenseClaw-owned, so an uninstall that
// runs before any reconcile migrated it does not strand the old command.
func TestRemoveWindowsCodexRequirementsOwnedChangesTakesUnboundCommands(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	contracts := KnownHookContracts("codex")
	opts.HookContractID = contracts[len(contracts)-1].ContractID
	for name, legacyCommand := range map[string]string{
		"call operator": legacyCallOperatorWindowsCodexManagedHookCommand(opts.HookBinary),
		"awaited":       windowsCodexManagedHookCommand(opts.HookBinary),
	} {
		t.Run(name, func(t *testing.T) {
			legacy := unboundWindowsCodexRequirementsForTest(t, opts, legacyCommand)
			cleaned, changed, err := removeWindowsCodexRequirementsOwnedChanges(legacy, []byte("administrator_key = \"preserve\"\n"), opts)
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Fatal("unbound DefenseClaw groups were not removed")
			}
			if strings.Contains(string(cleaned), legacyCommand) {
				t.Fatalf("unbound DefenseClaw groups survived removal:\n%s", cleaned)
			}
			if !strings.Contains(string(cleaned), `C:\AdministratorHooks\audit.exe`) {
				t.Fatalf("removal took the administrator's group:\n%s", cleaned)
			}
		})
	}
}

// unboundWindowsCodexRequirementsForTest renders the requirements a 26.8.x
// Secure Client release wrote (the matrix without a hook contract), then
// rewrites every DefenseClaw handler to command and appends an administrator
// group to the first event.
func unboundWindowsCodexRequirementsForTest(t *testing.T, opts WindowsCodexMachineRequirementsOptions, command string) []byte {
	t.Helper()
	unbound := opts
	unbound.HookContractID = ""
	current, _, err := reconcileWindowsCodexRequirements([]byte("administrator_key = \"preserve\"\n"), unbound, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseWindowsCodexRequirements(current)
	if err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	groups := windowsCodexMachineProfileGroups(unbound)
	for _, expected := range groups {
		for _, raw := range hooks[expected.eventType].([]interface{}) {
			handler := raw.(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
			handler["command"] = command
			handler["command_windows"] = command
		}
	}
	first := groups[0].eventType
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

// A bound machine command a 1.0.x release rendered as the awaited bridge
// (a launcher path the direct cmd.exe form cannot carry) without the
// Constrained Language fail-closed exit stays DefenseClaw's own.
func TestWindowsCodexRenderedHookCommandOwnsTheOneZeroBridge(t *testing.T) {
	hookBinary := `C:\Program Files (x86)\DefenseClaw\bin\defenseclaw-hook.exe`
	contracts := KnownHookContracts("codex")
	contract := contracts[len(contracts)-1].ContractID
	current := windowsCodexBoundManagedHookCommand(hookBinary, "PreToolUse", contract)
	if current != bridgeWindowsCodexBoundManagedHookCommand(hookBinary, "PreToolUse", contract) {
		t.Fatal("the launcher path did not select the bridge")
	}
	legacy, ok := legacyWindowsAwaitedHookCommand(current)
	if !ok || legacy == current {
		t.Fatal("no 1.0.x form of the bridge")
	}
	for _, command := range []string{current, legacy} {
		event, bound, owned := windowsCodexRenderedHookCommand(command, hookBinary)
		if !owned || event != "PreToolUse" || bound != contract {
			t.Fatalf("bridge not owned: event=%q contract=%q owned=%v", event, bound, owned)
		}
	}
}
