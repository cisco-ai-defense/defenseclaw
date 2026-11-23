// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1898: from 1.0.10 on the Local hook files name a launch image
// bin\hooks\<d16>\defenseclaw-hook.exe. An account signed out or disconnected
// through an upgrade keeps the earlier release's files, which name the earlier
// launch image, until the guardian rewrites them in the account's own session.
// The guardian's read-only verify that accepts an earlier release render takes
// them as current only for the earlier image the account's protected records
// name (RecordedHookBinary), and only in that verify: no recorded image,
// another bin or name, another launch image, a current-render verify and a
// placement still treat them as stale.
func TestGAP1898EnsureCopilotVSCodeUserAcceptsTheRecordedEarlierLaunchImageRender(t *testing.T) {
	const (
		bin       = `C:\Program Files\Cisco\DefenseClaw\bin`
		earlier   = bin + `\hooks\6081ba06f39a5eb8\defenseclaw-hook.exe`
		current   = bin + `\hooks\65b4297c1bc70cbd\defenseclaw-hook.exe`
		third     = bin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
		otherBin  = `C:\Program Files\Other\bin\hooks\6081ba06f39a5eb8\defenseclaw-hook.exe`
		otherName = bin + `\hooks\6081ba06f39a5eb8\other-hook.exe`
	)
	home := t.TempDir()
	ensure := func(hookBinary string, dryRun, acceptPrior bool, recorded string) CopilotVSCodeUserResult {
		t.Helper()
		result, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{
			Home: home, GOOS: "windows", HookBinary: hookBinary, HookFile: true, Plugin: true,
			DryRun: dryRun, AcceptPriorRelease: acceptPrior, RecordedHookBinary: recorded,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	stale := func(label string, result CopilotVSCodeUserResult) {
		t.Helper()
		if len(result.Changed) != 2 {
			t.Fatalf("%s: %+v, want both documents stale", label, result)
		}
	}
	// The earlier release placed its render for its own launch image.
	if result := ensure(earlier, false, false, ""); !result.HookFileOK || !result.PluginOK {
		t.Fatalf("earlier release placement: %+v", result)
	}

	stale("current-render verify", ensure(current, true, false, ""))
	stale("current-render verify with a recorded image", ensure(current, true, false, earlier))
	stale("prior-render verify without the recorded image", ensure(current, true, true, ""))
	for _, recorded := range []string{otherBin, otherName, third, current} {
		stale("prior-render verify recording "+recorded, ensure(current, true, true, recorded))
	}
	if result := ensure(current, true, true, earlier); len(result.Changed)+len(result.Removed)+len(result.Kept) != 0 ||
		!result.HookFileOK || !result.PluginOK {
		t.Fatalf("prior-render verify of the recorded earlier image's render: %+v, want nothing to change", result)
	}

	// Another launch image's render is not the recorded one.
	thirdRender, err := RenderCopilotVSCodeLocalHooks("windows", third)
	if err != nil {
		t.Fatal(err)
	}
	hookFile := CopilotVSCodeLocalHookFilePath(home)
	if err := os.WriteFile(hookFile, thirdRender, 0o600); err != nil {
		t.Fatal(err)
	}
	if result := ensure(current, true, true, earlier); len(result.Changed) != 1 {
		t.Fatalf("a third launch image's Local hook file with the earlier image recorded: %+v, want it stale", result)
	}

	// The tolerance never writes: a placement with it puts the current render.
	if result := ensure(current, false, true, earlier); len(result.Changed) != 2 {
		t.Fatalf("placement with the tolerance: %+v, want both documents rewritten", result)
	}
	want, err := RenderCopilotVSCodeLocalHooks("windows", current)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{hookFile, CopilotPluginHooksPath(home)} {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil || string(data) != string(want) {
			t.Fatalf("%s after placement: err=%v, want the current render", path, err)
		}
	}
}
