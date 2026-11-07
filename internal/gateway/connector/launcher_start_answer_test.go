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

// stubSiblingLauncherGuard makes every launcher have the one-line guard
// program beside it (present) or none.
func stubSiblingLauncherGuard(t *testing.T, present bool) {
	t.Helper()
	saved := windowsSiblingLauncherGuard
	windowsSiblingLauncherGuard = func(launcher string) string {
		if !present {
			return ""
		}
		return windowsSiblingGuardPath(launcher)
	}
	t.Cleanup(func() { windowsSiblingLauncherGuard = saved })
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
			stubSiblingLauncherGuard(t, true)
			got := windowsCodexHookCommandForBinaryEvent(event, contract.ContractID, launcher)
			if blocks && got != guarded || !blocks && got != direct {
				t.Fatalf("%s %s with the guard: %q; want guarded=%v", contract.ContractID, event, got, blocks)
			}
			if _, owned := nativeHookExactCommands([]string{launcher})[got]; !owned {
				t.Fatalf("%s %s: %q is not owned", contract.ContractID, event, got)
			}
			stubSiblingLauncherGuard(t, false)
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
	stubSiblingLauncherGuard(t, true)
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
	stubSiblingLauncherGuard(t, true)
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

// Every hook form this release added for a launcher that cannot start
// (launcherStartAnswerHookForms) is owned by its connector, so setup
// rewrites it and teardown removes it, and the Codex, Kiro and Devin forms
// are the ones their rollback converters turn into the earlier form. The
// Antigravity form is owned by its key, which the connector-wide rollback
// cleanup (GAP-0697) reads (rel-1-0-6 GAP-0676).
func TestLauncherStartAnswerHookFormsAreOwnedAndConverted(t *testing.T) {
	pinWindowsSystemDirectoryForTest(t)
	const launcher = `C:\Users\dcw std1\.local\bin\defenseclaw-hook.exe`
	setHookBinaryOverride(t, launcher)
	forms := launcherStartAnswerHookForms(launcher)
	if len(forms) != 4 || len(forms["antigravity"]) != 1 || len(forms["kiro"]) != 2 || len(forms["devin"]) != 3 || len(forms["codex"]) == 0 {
		t.Fatalf("forms = %d connectors (antigravity %d, kiro %d, codex %d, devin %d)", len(forms),
			len(forms["antigravity"]), len(forms["kiro"]), len(forms["codex"]), len(forms["devin"]))
	}
	contains := func(list []string, command string) bool {
		for _, item := range list {
			if item == command {
				return true
			}
		}
		return false
	}
	for _, command := range forms["antigravity"] {
		if command != antigravityHookInvocationCommandForEvent("windows", "PreToolUse", "") ||
			!contains(antigravityOwnedHookCommandsForOS("windows", ""), command) {
			t.Fatal("the Antigravity form is not the per-user PreToolUse render, or is not owned")
		}
	}
	kiroPairs := kiroWindowsHookFormPairs([]string{launcher})
	for _, command := range forms["kiro"] {
		converted := false
		for _, pair := range kiroPairs {
			converted = converted || pair[0] == command
		}
		if !converted || !contains(kiroWindowsOwnedHookCommands(), command) {
			t.Fatalf("a Kiro form is not owned (%v) or not converted (%v)", contains(kiroWindowsOwnedHookCommands(), command), converted)
		}
	}
	for _, command := range forms["codex"] {
		found := false
		for _, contract := range builtinHookContracts["codex"] {
			for _, event := range contract.Events {
				if !contains(windowsCodexPerUserHookCommands(event, contract.ContractID, launcher), command) {
					continue
				}
				bridge, ok := codexWindowsHookFormReplacement(command, event, launcher, true)
				if ok && bridge == windowsNativePowerShellHookCommandForCodexEvent(event, contract.ContractID, launcher) {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("a Codex form is not owned and converted: %.120q", command)
		}
	}
	devinOwned := devinOwnedHookCommandsForOS("windows", SetupOpts{}, "")
	devinPairs := devinWindowsHookFormPairs([]string{launcher}, false)
	for _, command := range forms["devin"] {
		converted := false
		for _, pairs := range devinPairs {
			for _, pair := range pairs {
				converted = converted || pair[0] == command
			}
		}
		if !converted || !contains(devinOwned, command) || !isDevinBashNativeHookCommand(command) {
			t.Fatalf("the Devin form %q is not owned or not converted", command)
		}
	}
}

// A managed (standalone) Windows Antigravity install keeps the PreToolUse
// bridge without the launcher-start answer, the form every release before
// 1.0.9 rendered, as managed Kiro does; per-user PreToolUse answers. Setup
// writes the managed form, and both stay owned (REVIEW-g676 S2).
func TestAntigravityManagedKeepsTheEarlierBridge(t *testing.T) {
	pinWindowsSystemDirectoryForTest(t)
	setHookBinaryOverride(t, `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`)
	owned := antigravityOwnedHookCommandsForOS("windows", "")
	isOwned := func(command string) bool {
		for _, item := range owned {
			if item == command {
				return true
			}
		}
		return false
	}
	for _, event := range antigravityLifecycleEvents {
		earlier := windowsNativePowerShellHookCommandForEvent("antigravity", event, defenseclawHookBinary())
		managed := antigravityHookCommandForEvent("windows", event, "", true)
		perUser := antigravityHookCommandForEvent("windows", event, "", false)
		if managed != earlier {
			t.Fatalf("%s: the managed command is not the earlier bridge", event)
		}
		if (event == "PreToolUse") == (perUser == earlier) {
			t.Fatalf("%s: per-user answers = %v, want it only on PreToolUse", event, perUser != earlier)
		}
		if perUser != antigravityHookInvocationCommandForEvent("windows", event, "") || !isOwned(managed) || !isOwned(perUser) {
			t.Fatalf("%s: the per-user or managed form is not owned", event)
		}
	}
	for _, managed := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "hooks.json")
		if err := patchAntigravityHooksFor(path, "", "windows", managed); err != nil {
			t.Fatal(err)
		}
		cfg, err := readJSONObject(path)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := cfg[antigravityOwnedHookKeyPrefix+"pretooluse"].(map[string]interface{})
		groups, _ := key["PreToolUse"].([]interface{})
		group, _ := groups[0].(map[string]interface{})
		handlers, _ := group["hooks"].([]interface{})
		handler, _ := handlers[0].(map[string]interface{})
		if got, want := handler["command"], antigravityHookCommandForEvent("windows", "PreToolUse", "", managed); got != want {
			t.Fatalf("managed=%v: Setup wrote %.80q, want %.80q", managed, got, want)
		}
	}
}

// Kiro starts its command through cmd.exe (cmd.exe /d /c, and Node adds
// cmd.exe /d /s /c "..."), whose command line holds at most 8191
// characters. The encoded bridge grows by about 5.3 characters per launcher
// path character, so it must fit with room to spare on a long profile path
// (REVIEW-g676 L2).
func TestKiroWindowsCommandFitsTheCmdExeLimitOnALongProfilePath(t *testing.T) {
	pinWindowsSystemDirectoryForTest(t)
	const cmdExeLimit, wrapper = 8191, 256
	profile := `C:\Users\` + strings.Repeat("d", 48) + ".CONTOSO-ENTERPRISE-0001"
	launcher := profile + `\.local\bin\defenseclaw-hook.exe`
	if len(launcher) < 100 {
		t.Fatalf("launcher path is only %d characters", len(launcher))
	}
	short := windowsKiroHookCommandForBinary(`C:\Users\a\.local\bin\defenseclaw-hook.exe`, KiroHookSurfaceV3, false)
	for _, surface := range []string{"", KiroHookSurfaceV3} {
		for _, managed := range []bool{false, true} {
			command := windowsKiroHookCommandForBinary(launcher, surface, managed)
			if len(command)+wrapper > cmdExeLimit {
				t.Fatalf("surface %q managed=%v: %d characters with a %d-character launcher path; cmd.exe takes %d with the wrapper",
					surface, managed, len(command), len(launcher), cmdExeLimit-wrapper)
			}
		}
	}
	perCharacter := float64(len(windowsKiroHookCommandForBinary(launcher, KiroHookSurfaceV3, false))-len(short)) /
		float64(len(launcher)-len(`C:\Users\a\.local\bin\defenseclaw-hook.exe`))
	t.Logf("Kiro v3 per-user command: %d characters on a %d-character path, %.1f per path character; headroom %d path characters",
		len(windowsKiroHookCommandForBinary(launcher, KiroHookSurfaceV3, false)), len(launcher), perCharacter,
		int(float64(cmdExeLimit-wrapper-len(windowsKiroHookCommandForBinary(launcher, KiroHookSurfaceV3, false)))/perCharacter))
}
