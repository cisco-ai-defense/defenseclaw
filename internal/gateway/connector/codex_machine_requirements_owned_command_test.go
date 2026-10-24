// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// windowsCodexTestEncoded is script as the system PowerShell
// -EncodedCommand line every managed Codex command uses.
func windowsCodexTestEncoded(script string) string {
	return windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand " + powershellEncodedCommand(script)
}

// windowsCodexTestScript is the decoded script of command.
func windowsCodexTestScript(t *testing.T, command string) string {
	t.Helper()
	prefix := windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand "
	script, ok := powershellDecodedCommand(strings.TrimPrefix(command, prefix))
	if !ok {
		t.Fatalf("not an encoded command: %q", command)
	}
	return script
}

// windowsCodexAdministratorLookalikes are administrator commands that name
// the DefenseClaw hook launcher and the managed Codex flags without being a
// command DefenseClaw renders. Every one of them used to count as
// DefenseClaw's (a substring match on the decoded script).
func windowsCodexAdministratorLookalikes(t *testing.T, opts WindowsCodexMachineRequirementsOptions) map[string]string {
	t.Helper()
	current := windowsCodexBoundManagedHookCommand(opts.HookBinary, "PreToolUse", opts.HookContractID)
	legacy := legacyStartProcessWindowsCodexBoundManagedHookCommand(opts.HookBinary, "PreToolUse", opts.HookContractID)
	extraArgument := []string{"hook", "--connector", "codex", "--enterprise-managed", "--event", "PreToolUse", "--hook-contract", opts.HookContractID, "--debug"}
	return map[string]string{
		"diagnostic text": windowsCodexTestEncoded(strings.Join([]string{
			"$ErrorActionPreference='Stop'",
			"$dc=" + powershellQuoteLiteral(opts.HookBinary),
			"Write-Host \"audit runs next to $dc hook --connector codex --enterprise-managed\"",
			"& 'C:\\Tools\\audit.exe'",
			"exit $LASTEXITCODE",
		}, "; ")),
		"the current command with a statement appended": windowsCodexTestEncoded(windowsCodexTestScript(t, current) + "; & 'C:\\Tools\\audit.exe'"),
		"the 1.0.0 command with a statement prepended":  windowsCodexTestEncoded("& 'C:\\Tools\\audit.exe'; " + windowsCodexTestScript(t, legacy)),
		"the unbound command with a statement appended": windowsCodexTestEncoded(windowsCodexTestScript(t, windowsCodexManagedHookCommand(opts.HookBinary)) + "; Write-Host done"),
		"the launcher with an extra argument":           windowsCodexTestEncoded(strings.Join(append([]string{"$ErrorActionPreference='Stop'", "$env:NoDefaultCurrentDirectoryInExePath='1'"}, windowsAwaitedHookStatements(opts.HookBinary, extraArgument)...), "; ")),
		"the current script outside -EncodedCommand":    windowsSystemPowerShellExe() + " -NoLogo -NoProfile -Command \"" + windowsCodexTestScript(t, current) + "\"",
		"the current command for another launcher":      windowsCodexBoundManagedHookCommand(`C:\Tools\defenseclaw-hook.exe`, "PreToolUse", opts.HookContractID),
		"the current command with trailing arguments":   current + " -Version 5",
	}
}

// Ownership of a Windows Codex machine group is a group DefenseClaw renders
// around a command DefenseClaw renders, byte for byte: every group any
// release writes (standalone on every hook contract, Secure Client, the
// unbound command, the 1.0.0 form) is DefenseClaw's under its event, and no
// administrator script that only names the launcher or the managed flags is.
func TestWindowsCodexOwnedHookCommandIsOnlyARenderedCommand(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	contracts := KnownHookContracts("codex")
	opts.HookContractID = contracts[len(contracts)-1].ContractID
	type rendered struct {
		name string
		opts WindowsCodexMachineRequirementsOptions
		form func(event, contract string) string
	}
	forms := []rendered{{name: "unbound", opts: testWindowsCodexMachineOptions()}}
	for _, contract := range contracts {
		for _, secureClient := range []bool{false, true} {
			variant := testWindowsCodexMachineOptions()
			variant.HookContractID = contract.ContractID
			variant.SecureClient = secureClient
			forms = append(forms, rendered{name: contract.ContractID, opts: variant})
		}
		legacy := testWindowsCodexMachineOptions()
		legacy.HookContractID = contract.ContractID
		forms = append(forms, rendered{name: contract.ContractID + " 1.0.0", opts: legacy, form: func(event, contract string) string {
			return legacyStartProcessWindowsCodexBoundManagedHookCommand(legacy.HookBinary, event, contract)
		}})
	}
	for _, form := range forms {
		layout := windowsCodexMachineLayout(form.opts)
		if form.form != nil {
			layout.handler = func(group codexHookGroup) map[string]interface{} {
				return windowsCodexMachineHandler(form.form(group.eventType, form.opts.HookContractID), group.timeout)
			}
		}
		for _, group := range layout.groups {
			raw := windowsCodexTestNormalized(t, layout.expectedGroup(group))
			if !windowsCodexOwnedHookGroup(raw, group.eventType, opts.HookBinary) {
				t.Errorf("%s: DefenseClaw's %s group is not recognized: %v", form.name, group.eventType, raw)
			}
			command := layout.handler(group)["command"].(string)
			event, contract, ok := windowsCodexRenderedHookCommand(command, opts.HookBinary)
			if !ok || form.opts.HookContractID != "" && (event != group.eventType || contract != form.opts.HookContractID) {
				t.Errorf("%s: DefenseClaw's %s command reads as %q %q %t", form.name, group.eventType, event, contract, ok)
			}
		}
	}
	for name, command := range windowsCodexAdministratorLookalikes(t, opts) {
		if _, _, ok := windowsCodexRenderedHookCommand(command, opts.HookBinary); ok {
			t.Errorf("%s: an administrator command counts as DefenseClaw's", name)
		}
	}
	current := windowsCodexBoundManagedHookCommand(opts.HookBinary, "PreToolUse", opts.HookContractID)
	if _, _, ok := windowsCodexRenderedHookCommand(current, ""); ok {
		t.Error("a command counts as DefenseClaw's for an empty launcher")
	}
	if _, _, ok := windowsCodexRenderedHookCommand("", opts.HookBinary); ok {
		t.Error("an empty command counts as DefenseClaw's")
	}
}

// A standalone uninstall, a reconcile (install, upgrade, repair) and the
// stale-layout strip remove or replace only DefenseClaw's groups. An
// administrator group whose script names the DefenseClaw launcher and the
// managed Codex flags stays in every one of them, and its reference to the
// launcher keeps the binary removal unsafe.
func TestWindowsCodexLifecycleKeepsAnAdministratorScriptThatNamesTheHook(t *testing.T) {
	earlier := testWindowsCodexMachineOptions()
	contracts := KnownHookContracts("codex")
	earlier.HookContractID = contracts[0].ContractID
	current := testWindowsCodexMachineOptions()
	current.HookContractID = contracts[len(contracts)-1].ContractID
	for name, command := range windowsCodexAdministratorLookalikes(t, current) {
		t.Run(name, func(t *testing.T) {
			adminGroup := map[string]interface{}{"matcher": "*", "hooks": []interface{}{
				map[string]interface{}{"type": "command", "command": command, "command_windows": command, "timeout": int64(5)},
			}}
			adminFile, err := toml.Marshal(map[string]interface{}{
				"approval_policy_floor": "on-request",
				"hooks":                 map[string]interface{}{"PreToolUse": []interface{}{adminGroup}},
			})
			if err != nil {
				t.Fatal(err)
			}
			countAdmin := func(t *testing.T, raw []byte) int {
				t.Helper()
				cfg, err := parseWindowsCodexRequirements(raw)
				if err != nil {
					t.Fatal(err)
				}
				hooks, _ := cfg["hooks"].(map[string]interface{})
				groups, _ := hooks["PreToolUse"].([]interface{})
				found := 0
				for _, group := range groups {
					handlers, _ := group.(map[string]interface{})["hooks"].([]interface{})
					if len(handlers) == 1 && handlers[0].(map[string]interface{})["command"] == command {
						found++
					}
				}
				return found
			}
			// The managed files with the administrator group in them, built
			// without reconcile so that removal is checked on its own.
			withAdmin := func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) []byte {
				t.Helper()
				managed, _, err := reconcileWindowsCodexRequirements([]byte("approval_policy_floor = \"on-request\"\n"), opts, true)
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := parseWindowsCodexRequirements(managed)
				if err != nil {
					t.Fatal(err)
				}
				hooks := cfg["hooks"].(map[string]interface{})
				hooks["PreToolUse"] = append([]interface{}{adminGroup}, hooks["PreToolUse"].([]interface{})...)
				raw, err := toml.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			written, upgraded := withAdmin(t, earlier), withAdmin(t, current)
			for _, install := range []struct {
				name string
				file []byte
				opts WindowsCodexMachineRequirementsOptions
			}{
				{name: "install over the administrator file", file: adminFile, opts: current},
				{name: "upgrade from the earlier release", file: written, opts: current},
				{name: "repair of the current release", file: upgraded, opts: current},
			} {
				reconciled, _, err := reconcileWindowsCodexRequirements(install.file, install.opts, true)
				if err != nil {
					t.Fatal(err)
				}
				if countAdmin(t, reconciled) != 1 {
					t.Errorf("%s replaced the administrator group:\n%s", install.name, reconciled)
				}
			}
			for _, removal := range []struct {
				name           string
				file, baseline []byte
			}{
				{name: "earlier release over the administrator preimage", file: written, baseline: adminFile},
				{name: "earlier release recorded as its own preimage", file: written, baseline: written},
				{name: "current release over the administrator preimage", file: upgraded, baseline: adminFile},
			} {
				cleaned, _, err := removeWindowsCodexRequirementsOwnedChanges(removal.file, removal.baseline, current)
				if err != nil {
					t.Fatal(err)
				}
				if countAdmin(t, cleaned) != 1 {
					t.Errorf("%s: uninstall deleted the administrator group:\n%s", removal.name, cleaned)
					continue
				}
				if leftovers, err := windowsCodexRequirementsHoldOwnedLeftovers(cleaned, current); err != nil || leftovers {
					t.Fatalf("%s: DefenseClaw content left = %t, %v:\n%s", removal.name, leftovers, err, cleaned)
				}
				if exact, err := windowsCodexRequirementsContainExactManagedHook(cleaned, current); err != nil || exact {
					t.Fatalf("%s: an exact DefenseClaw group survived = %t, %v:\n%s", removal.name, exact, err, cleaned)
				}
				if strings.Contains(command, current.HookBinary) || strings.Contains(windowsCodexTestScriptOrEmpty(command), current.HookBinary) {
					references, err := windowsCodexOwnedPathReferenceCount(cleaned, current)
					if err != nil {
						t.Fatal(err)
					}
					if references == 0 {
						t.Fatalf("%s: the administrator reference to the launcher does not keep the binary", removal.name)
					}
				}
			}
			stripped, _, err := stripWindowsCodexLayout(upgraded, current.HookBinary, current.ManagedDir)
			if err != nil {
				t.Fatal(err)
			}
			if countAdmin(t, stripped) != 1 {
				t.Fatalf("the layout strip deleted the administrator group:\n%s", stripped)
			}
		})
	}
}

func windowsCodexTestScriptOrEmpty(command string) string {
	prefix := windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand "
	script, _ := powershellDecodedCommand(strings.TrimPrefix(command, prefix))
	return script
}
