// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0980: a read-only verify that accepts the Local hook files of releases up
// to 1.0.6 takes a document that holds exactly that render as current, and only
// that: a mixed document, a current-render verify and a placement still treat
// it as stale.
func TestEnsureCopilotVSCodeUserAcceptsTheEarlierReleasesRenderOnlyWhenAsked(t *testing.T) {
	const hookBinary = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	home := t.TempDir()
	request := func(dryRun, acceptPrior bool) CopilotVSCodeUserResult {
		t.Helper()
		result, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{
			Home: home, GOOS: "windows", HookBinary: hookBinary, HookFile: true, Plugin: true,
			DryRun: dryRun, AcceptPriorRelease: acceptPrior,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := request(false, false); !result.HookFileOK || !result.PluginOK {
		t.Fatalf("placement: %+v", result)
	}
	current, err := RenderCopilotVSCodeLocalHooks("windows", hookBinary)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := renderCopilotVSCodeLocalHooksPriorRelease("windows", hookBinary)
	if err != nil {
		t.Fatal(err)
	}
	if string(prior) == string(current) {
		t.Fatal("the earlier release's render is the current one on Windows")
	}
	hookFile := CopilotVSCodeLocalHookFilePath(home)
	pluginHooks := CopilotPluginHooksPath(home)
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(hookFile, prior)
	write(pluginHooks, prior)

	if result := request(true, false); len(result.Changed) != 2 {
		t.Fatalf("current-render verify of the earlier render: %+v, want both documents changed", result)
	}
	if result := request(true, true); len(result.Changed)+len(result.Removed)+len(result.Kept) != 0 || !result.HookFileOK || !result.PluginOK {
		t.Fatalf("prior-render verify of the earlier render: %+v, want nothing to change", result)
	}
	// One document current, one earlier: each is judged on its own.
	write(hookFile, current)
	if result := request(true, true); len(result.Changed)+len(result.Removed) != 0 {
		t.Fatalf("one current, one earlier document: %+v", result)
	}
	// A mixed document is neither render.
	mixed := strings.Replace(string(prior), "PreToolUse", "PreToolUse", 1)
	mixed = strings.Replace(mixed, strings.Split(string(current), `"command": "`)[1][:40], "X"+strings.Split(string(current), `"command": "`)[1][1:40], 1)
	write(hookFile, []byte(mixed))
	if result := request(true, true); len(result.Changed)+len(result.Kept) == 0 && result.HookFileOK {
		t.Fatalf("a document that is neither render passed: %+v", result)
	}
	// The tolerance never writes: a placement with it puts the current render.
	write(hookFile, prior)
	write(pluginHooks, prior)
	if result := request(false, true); len(result.Changed) != 2 {
		t.Fatalf("placement with the tolerance: %+v, want both documents rewritten", result)
	}
	for _, path := range []string{hookFile, pluginHooks} {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil || string(data) != string(current) {
			t.Fatalf("%s after placement: err=%v, want the current render", path, err)
		}
	}
}

// GAP-1096: releases up to 1.0.9 wrote the Local hook files for the transition
// image bin\defenseclaw-hook.exe. An account signed out or disconnected through
// the upgrade to the 1.0.10 launch image keeps them until the guardian rewrites
// them in its own session, and Setup replaces that image in place with this
// release hook, so the read-only verify that accepts an earlier release render
// takes them as current. Only that image of the same bin: another folder, a
// placement and a current-render verify still treat it as stale.
func TestEnsureCopilotVSCodeUserAcceptsTheTransitionImageRenderOnlyWhenAsked(t *testing.T) {
	const (
		bin        = `C:\Program Files\Cisco\DefenseClaw\bin`
		launch     = bin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
		transition = bin + `\defenseclaw-hook.exe`
		otherBin   = `C:\Program Files\Other\bin\defenseclaw-hook.exe`
	)
	home := t.TempDir()
	request := func(dryRun, acceptPrior bool) CopilotVSCodeUserResult {
		t.Helper()
		result, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{
			Home: home, GOOS: "windows", HookBinary: launch, HookFile: true, Plugin: true,
			DryRun: dryRun, AcceptPriorRelease: acceptPrior,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := request(false, false); !result.HookFileOK || !result.PluginOK {
		t.Fatalf("placement: %+v", result)
	}
	render := func(f func(string, string) ([]byte, error), binary string) []byte {
		t.Helper()
		data, err := f("windows", binary)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	current := render(RenderCopilotVSCodeLocalHooks, launch)
	hookFile := CopilotVSCodeLocalHookFilePath(home)
	pluginHooks := CopilotPluginHooksPath(home)
	write := func(data []byte) {
		t.Helper()
		for _, path := range []string{hookFile, pluginHooks} {
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, earlier := range [][]byte{
		render(RenderCopilotVSCodeLocalHooks, transition),             // 1.0.7 to 1.0.9
		render(renderCopilotVSCodeLocalHooksPriorRelease, transition), // up to 1.0.6
	} {
		write(earlier)
		if result := request(true, false); len(result.Changed) != 2 {
			t.Fatalf("current-render verify of the transition-image render: %+v, want both documents changed", result)
		}
		if result := request(true, true); len(result.Changed)+len(result.Removed)+len(result.Kept) != 0 ||
			!result.HookFileOK || !result.PluginOK {
			t.Fatalf("prior-render verify of the transition-image render: %+v, want nothing to change", result)
		}
	}
	// The image of another install bin is not this install hook.
	write(render(RenderCopilotVSCodeLocalHooks, otherBin))
	if result := request(true, true); len(result.Changed)+len(result.Kept) == 0 && result.HookFileOK {
		t.Fatalf("a render for another install bin passed: %+v", result)
	}
	// The tolerance never writes: a placement puts the launch-image render.
	write(render(RenderCopilotVSCodeLocalHooks, transition))
	if result := request(false, true); len(result.Changed) != 2 {
		t.Fatalf("placement with the tolerance: %+v, want both documents rewritten", result)
	}
	for _, path := range []string{hookFile, pluginHooks} {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil || string(data) != string(current) {
			t.Fatalf("%s after placement: err=%v, want the current render", path, err)
		}
	}
}
