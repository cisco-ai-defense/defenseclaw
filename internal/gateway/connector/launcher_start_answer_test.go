// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

// stubCodexLauncherGuard makes every launcher have the one-line guard
// program beside it (present) or none.
func stubCodexLauncherGuard(t *testing.T, present bool) {
	t.Helper()
	saved := windowsCodexLauncherGuard
	windowsCodexLauncherGuard = func(launcher string) string {
		if !present {
			return ""
		}
		return windowsCodexSiblingGuardPath(launcher)
	}
	t.Cleanup(func() { windowsCodexLauncherGuard = saved })
}

func pinWindowsSystemDirectoryForTest(t *testing.T) {
	t.Helper()
	saved := windowsSystemDirectory
	windowsSystemDirectory = func() string { return `C:\Windows\System32` }
	t.Cleanup(func() { windowsSystemDirectory = saved })
}

// A nil answer renders the bridge every earlier release wrote, byte for byte,
// so managed renders, which never pass an answer, are unchanged
// (rel-1-0-6 GAP-0676).
func TestAnsweringBridgeWithoutAnAnswerIsTheEarlierBridge(t *testing.T) {
	pinWindowsSystemDirectoryForTest(t)
	const launcher = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	for _, tc := range []struct{ connector, event, contract string }{
		{"codex", "PreToolUse", "codex-hooks-v4"},
		{"antigravity", "PostToolUse", ""},
		{"kiro", "", ""},
		{"copilot", "preToolUse", ""},
	} {
		want := windowsNativePowerShellHookCommandForBoundEvent(tc.connector, tc.event, tc.contract, launcher, "--enterprise-managed")
		if got := windowsAnsweringPowerShellHookCommand(tc.connector, tc.event, tc.contract, launcher, nil, "--enterprise-managed"); got != want {
			t.Fatalf("%s: nil answer changed the bridge", tc.connector)
		}
	}
	for _, surface := range []string{"", KiroHookSurfaceV3} {
		managed := decodePowerShellEncodedCommandForTest(t, windowsKiroPowerShellBridgeForBinary(launcher, surface, true))
		perUser := decodePowerShellEncodedCommandForTest(t, windowsKiroPowerShellBridgeForBinary(launcher, surface, false))
		before := decodePowerShellEncodedCommandForTest(t, windowsKiroPowerShellBridge(launcher, surface, false, nil))
		if strings.Contains(managed, "try {") || strings.Contains(before, "try {") {
			t.Fatalf("surface %q: the managed or earlier Kiro bridge answers a launcher that cannot start", surface)
		}
		for _, want := range []string{
			"try { $hookProcess=[System.Diagnostics.Process]::Start($hookStart) } catch { ",
			"if ($null -eq $LASTEXITCODE -or $LASTEXITCODE -lt 0) { ",
			"if ($hookProcess.ExitCode -lt 0) { ",
			"its Kiro hook launcher cannot start", "exit 2 }",
		} {
			if !strings.Contains(perUser, want) {
				t.Fatalf("surface %q: the per-user Kiro bridge lacks %q:\n%s", surface, want, perUser)
			}
		}
	}
	direct, _ := windowsCmdDirectHookCommand(launcher, windowsCodexBoundManagedHookArguments("PreToolUse", "codex-hooks-v4"))
	if got := windowsCodexBoundManagedHookCommand(launcher, "PreToolUse", "codex-hooks-v4"); got != direct {
		t.Fatalf("managed Codex command = %q, want the direct start %q", got, direct)
	}
}

// The per-user Codex command of each event (rel-1-0-6 GAP-0676): the guarded
// start where Codex can block and the guard program is there, otherwise the
// direct start, and the answering bridge for a launcher path the direct form
// cannot carry. Stops never get the guard.
func TestCodexPerUserCommandStartsTheGuardOnTheEventsCodexCanBlock(t *testing.T) {
	pinWindowsSystemDirectoryForTest(t)
	const launcher = `C:\Users\dcw std1\.local\bin\defenseclaw-hook.exe`
	guard := `C:\Users\dcw std1\.local\bin\` + windowsHookGuardBinaryName
	for _, contract := range builtinHookContracts["codex"] {
		for _, event := range contract.Events {
			args := nativeHookBridgeArguments("codex", event, contract.ContractID, nil)
			direct, _ := windowsCmdDirectHookCommand(launcher, args)
			guarded := windowsSystemCmdExe() + ` /d /v:off /c "` + guard + `" ` + hookguard.SiblingSubcommand + " " + strings.Join(args, " ")
			blocks := hookguard.CodexBlock(event, contract.ContractID, "m") != nil
			stubCodexLauncherGuard(t, true)
			got := windowsCodexHookCommandForBinaryEvent(event, contract.ContractID, launcher)
			if blocks && got != guarded || !blocks && got != direct {
				t.Fatalf("%s %s with the guard: %q; want guarded=%v", contract.ContractID, event, got, blocks)
			}
			if _, owned := nativeHookExactCommands([]string{launcher})[got]; !owned {
				t.Fatalf("%s %s: %q is not owned", contract.ContractID, event, got)
			}
			stubCodexLauncherGuard(t, false)
			if got := windowsCodexHookCommandForBinaryEvent(event, contract.ContractID, launcher); got != direct {
				t.Fatalf("%s %s without the guard: %q; want the direct start", contract.ContractID, event, got)
			}
			// Every earlier form stays owned for repair and teardown.
			for _, earlier := range []string{
				direct, guarded,
				windowsNativePowerShellHookCommandForCodexEvent(event, contract.ContractID, launcher),
			} {
				if _, owned := nativeHookExactCommands([]string{launcher})[earlier]; !owned {
					t.Fatalf("%s %s: %q is not owned", contract.ContractID, event, earlier)
				}
			}
		}
	}
	for _, event := range []string{"Stop", "SubagentStop", "SessionEnd"} {
		if codexLauncherStartAnswer(event, "codex-hooks-v4") != nil {
			t.Fatalf("%s gets a blocking answer", event)
		}
	}
	// A launcher path cmd.exe cannot carry keeps the bridge, which answers a
	// launcher that cannot start on an event Codex can block.
	const odd = `C:\Users\a(1)\.local\bin\defenseclaw-hook.exe`
	stubCodexLauncherGuard(t, true)
	bridge := windowsCodexHookCommandForBinaryEvent("UserPromptSubmit", "codex-hooks-v4", odd)
	script := decodePowerShellEncodedCommandForTest(t, bridge)
	if !strings.Contains(script, `'{"decision":"block","reason":"DefenseClaw blocked this: its Codex hook launcher cannot start.`) {
		t.Fatalf("bridge does not answer Codex's block:\n%s", script)
	}
	if stop := windowsCodexHookCommandForBinaryEvent("Stop", "codex-hooks-v4", odd); stop != windowsNativePowerShellHookCommandForCodexEvent("Stop", "codex-hooks-v4", odd) {
		t.Fatalf("Stop bridge = %q, want the earlier bridge", stop)
	}
}

// Before a rollback the guarded start becomes the bridge every earlier
// release owns, with its trust; an aborted rollback puts the guarded start
// back (rel-1-0-6 GAP-0676, the GAP-1284 rule).
func TestCodexRollbackConvertsTheGuardedStartToTheEarlierBridgeAndBack(t *testing.T) {
	pinWindowsSystemDirectoryForTest(t)
	stubCodexLauncherGuard(t, true)
	const launcher = `C:\Users\dcw std1\.local\bin\defenseclaw-hook.exe`
	const contract = "codex-hooks-v4"
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previousPath := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousPath })
	handler := func(command string) map[string]interface{} {
		return map[string]interface{}{"type": "command", "command": command, "command_windows": command, "timeout": 30}
	}
	guarded := windowsCodexHookCommandForBinaryEvent("PreToolUse", contract, launcher)
	stop := windowsCodexHookCommandForBinaryEvent("Stop", contract, launcher)
	if !strings.Contains(guarded, hookguard.SiblingSubcommand) || strings.Contains(stop, hookguard.SiblingSubcommand) {
		t.Fatalf("PreToolUse %q, Stop %q", guarded, stop)
	}
	hooks := map[string]interface{}{
		"PreToolUse": []interface{}{map[string]interface{}{"matcher": "*", "hooks": []interface{}{handler(guarded)}}},
		"Stop":       []interface{}{map[string]interface{}{"hooks": []interface{}{handler(stop)}}},
	}
	keySource := codexHookStateKeySource(configPath)
	group := hooks["PreToolUse"].([]interface{})[0].(map[string]interface{})
	hash, err := codexCommandHookHashForPlatform("windows", "pre_tool_use", group["matcher"], group["hooks"].([]interface{})[0].(map[string]interface{}))
	if err != nil {
		t.Fatal(err)
	}
	preKey := codexHookStateKey(keySource, "pre_tool_use", 0, 0)
	hooks["state"] = map[string]interface{}{preKey: map[string]interface{}{"trusted_hash": hash}}
	original, err := toml.Marshal(map[string]interface{}{"hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: filepath.Join(dir, "data"), HookExecutable: launcher}
	if count, err := convertCodexConfigHookForms(opts, true, nil); err != nil || count != 2 {
		t.Fatalf("convert = %d, %v; want 2 handlers", count, err)
	}
	converted, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]interface{}{}
	if err := parseCodexTOML(converted, &cfg); err != nil {
		t.Fatal(err)
	}
	got := cfg["hooks"].(map[string]interface{})
	for _, event := range []string{"PreToolUse", "Stop"} {
		h := got[event].([]interface{})[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
		if want := windowsNativePowerShellHookCommandForCodexEvent(event, contract, launcher); h["command"] != want || h["command_windows"] != want {
			t.Fatalf("%s handler = %v; want the earlier bridge", event, h["command"])
		}
	}
	preGroup := got["PreToolUse"].([]interface{})[0].(map[string]interface{})
	newHash, err := codexCommandHookHashForPlatform("windows", "pre_tool_use", preGroup["matcher"], preGroup["hooks"].([]interface{})[0].(map[string]interface{}))
	if err != nil {
		t.Fatal(err)
	}
	if got["state"].(map[string]interface{})[preKey].(map[string]interface{})["trusted_hash"] != newHash {
		t.Fatal("trust of the converted guarded handler was not carried over")
	}
	if count, err := convertCodexConfigHookForms(opts, false, nil); err != nil || count != 2 {
		t.Fatalf("restore = %d, %v; want 2 handlers", count, err)
	}
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(restored, []byte(hookguard.SiblingSubcommand)) {
		t.Fatalf("restore did not put the guarded start back:\n%s", restored)
	}
}
