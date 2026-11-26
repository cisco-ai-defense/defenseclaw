// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"path/filepath"
	"strings"
	"testing"
)

// GAP-2281: a DefenseClaw launcher or guard renamed in place inside the
// Windows Codex direct cmd.exe start is claimed only with DefenseClaw's exact
// Codex event and contract binding; every near miss stays the operator's.
func TestGAP2281CodexRenamedCmdDirectOwnershipParity(t *testing.T) {
	dir := t.TempDir()
	launcherDir := filepath.Join(dir, "DefenseClaw")
	setHookBinaryOverride(t, filepath.Join(launcherDir, windowsHookBinaryName))
	hooksDir := filepath.Join(dir, ".defenseclaw", "hooks")
	contracts := builtinHookContracts["codex"]
	if len(contracts) == 0 || len(contracts[0].Events) == 0 {
		t.Fatal("no Codex hook contract")
	}
	contract, event := contracts[0].ContractID, contracts[0].Events[0]
	arguments := nativeHookBridgeArguments("codex", event, contract, nil)
	render := func(program string, args []string) string {
		t.Helper()
		command, ok := windowsCmdDirectHookCommand(program, args)
		if !ok {
			t.Fatalf("direct form cannot carry %s", filepath.Base(program))
		}
		return command
	}
	renamed := filepath.Join(launcherDir, "defenseclaw-hook-edited.exe")
	renamedGuard := filepath.Join(launcherDir, "defenseclaw-hook-guard-edited.exe")
	guarded, ok := windowsCodexGuardedHookCommand(renamedGuard, event, contract)
	if !ok {
		t.Fatal("guarded form cannot carry the renamed guard")
	}
	owned := map[string]string{
		"current launcher":      render(filepath.Join(launcherDir, windowsHookBinaryName), arguments),
		"renamed launcher":      render(renamed, arguments),
		"renamed guard":         guarded,
		"renamed, last binding": render(renamed, nativeHookBridgeArguments("codex", contracts[len(contracts)-1].Events[len(contracts[len(contracts)-1].Events)-1], contracts[len(contracts)-1].ContractID, nil)),
	}
	foreignDir := filepath.Join(dir, "OtherProduct")
	direct := render(renamed, arguments)
	foreign := map[string]string{
		"foreign folder, our name":    render(filepath.Join(foreignDir, windowsHookBinaryName), arguments),
		"foreign folder, edited name": render(filepath.Join(foreignDir, "defenseclaw-hook-edited.exe"), arguments),
		"other program beside ours":   render(filepath.Join(launcherDir, "other-tool.exe"), arguments),
		"other connector":             render(renamed, nativeHookBridgeArguments("claudecode", event, contract, nil)),
		"unknown event":               render(renamed, nativeHookBridgeArguments("codex", "NotAnEvent", contract, nil)),
		"unknown contract":            render(renamed, nativeHookBridgeArguments("codex", event, "not-a-contract", nil)),
		"no contract":                 render(renamed, nativeHookBridgeArguments("codex", event, "", nil)),
		"extra argument":              render(renamed, append(append([]string{}, arguments...), "--extra")),
		"guard argv on launcher":      render(renamed, append([]string{"launcher-guard-sibling"}, arguments...)),
		"trailing space":              direct + " ",
		"no /d":                       strings.Replace(direct, " /d ", " ", 1),
		"other cmd.exe":               strings.Replace(direct, windowsSystemCmdExe(), `C:\Tools\cmd.exe`, 1),
		"unquoted program":            strings.Replace(strings.Replace(direct, `"`, "", 1), `"`, "", 1),
	}
	for name, command := range owned {
		for _, key := range []string{"command", "command_windows"} {
			if !isOwnedCodexHookHandler(map[string]interface{}{"type": "command", key: command}, hooksDir) {
				t.Errorf("%s in %s: not claimed", name, key)
			}
		}
	}
	for name, command := range foreign {
		for _, key := range []string{"command", "command_windows"} {
			if isOwnedCodexHookHandler(map[string]interface{}{"type": "command", key: command}, hooksDir) {
				t.Errorf("%s in %s: claimed", name, key)
			}
		}
	}
	group := map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": owned["renamed launcher"]}}}
	if !isOwnedCodexHookGroup(group, hooksDir) {
		t.Error("VerifyClean group check does not report the renamed launcher")
	}
	group = map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": foreign["foreign folder, edited name"]}}}
	if isOwnedCodexHookGroup(group, hooksDir) {
		t.Error("VerifyClean group check reports a foreign hook")
	}
}
