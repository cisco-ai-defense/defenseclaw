// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// windowsHookBridgesFixture is scripts/live-connector-e2e/testdata/windows-hook-bridges.json:
// the decoded scripts of the PowerShell bridges setup writes on Windows.
//
// Its consumer is the Windows connector contract harness, scripts/live-connector-e2e/
// run-windows-install.ps1 (-Operation self-test, added by fix/r109-g088r), whose
// Get-AwaitedHookBridge parser must read every bridge exactly as this package renders it. The
// file is generator output, byte-identical on both branches; this test is its generator's guard:
// when the bridge text changes, this fails in Go CI and the file is regenerated together with
// the parser, not first found red in the Windows contract.
const windowsHookBridgesFixture = "../../../scripts/live-connector-e2e/testdata/windows-hook-bridges.json"

// TestWindowsHookBridgesEqualTheContractFixture renders the 11 bridges the contract harness
// reads and compares each, byte for byte, with the fixture (review g088r S2).
func TestWindowsHookBridgesEqualTheContractFixture(t *testing.T) {
	pinWindowsSystemDirectoryForTest(t)
	const (
		agy      = `C:\Users\u\.local\bin\defenseclaw-hook.exe`
		codexBin = `C:\Users\a(1)\.local\bin\defenseclaw-hook.exe`
	)
	antigravity := func(event string) string {
		return windowsAnsweringPowerShellHookCommand("antigravity", event, "", agy, antigravityLauncherStartAnswer(event))
	}
	codex := func(event, contract string) string {
		return windowsCodexAnsweringBridgeHookCommand(event, contract, codexBin)
	}
	rendered := []struct{ name, hook, command string }{
		{"antigravity/PreToolUse", agy, antigravity("PreToolUse")},
		{"codex/codex-hooks-v1/PreToolUse", codexBin, codex("PreToolUse", "codex-hooks-v1")},
	}
	for _, event := range []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact", "PostCompact"} {
		rendered = append(rendered, struct{ name, hook, command string }{"codex/codex-hooks-v4/" + event, codexBin, codex(event, "codex-hooks-v4")})
	}
	// Events that get no answer keep the earlier bridge shape.
	rendered = append(rendered,
		struct{ name, hook, command string }{"antigravity/PostToolUse/unanswered", agy, antigravity("PostToolUse")},
		struct{ name, hook, command string }{"codex/codex-hooks-v4/Stop/unanswered", codexBin, codex("Stop", "codex-hooks-v4")},
	)

	data, err := os.ReadFile(filepath.FromSlash(windowsHookBridgesFixture))
	if err != nil {
		t.Fatalf("read the contract fixture: %v", err)
	}
	var fixture struct {
		Bridges []struct {
			Name   string `json:"name"`
			Hook   string `json:"hook"`
			Script string `json:"script"`
		} `json:"bridges"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse the contract fixture: %v", err)
	}
	if len(fixture.Bridges) != len(rendered) {
		t.Fatalf("fixture has %d bridges, the generator renders %d", len(fixture.Bridges), len(rendered))
	}
	for i, want := range rendered {
		got := fixture.Bridges[i]
		if got.Name != want.name || got.Hook != want.hook {
			t.Fatalf("fixture entry %d is %q (%s), want %q (%s)", i, got.Name, got.Hook, want.name, want.hook)
		}
		if script := decodePowerShellEncodedCommandForTest(t, want.command); script != got.Script {
			t.Errorf("%s: the bridge setup writes is not the fixture's.\nrendered: %s\nfixture:  %s\nRegenerate windows-hook-bridges.json and update the contract harness parser (run-windows-install.ps1 Get-AwaitedHookBridge) together.", want.name, script, got.Script)
		}
	}
}
