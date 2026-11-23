// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1898 golden: testdata/copilot-vscode-1.0.10/windows-hooks.json is the
// Local hook file DefenseClaw 1.0.10 wrote on a managed Windows computer, taken
// from the account's profile (launch image 6081ba06f39a5eb8). An account
// signed out or disconnected through the upgrade keeps it. The guardian's
// read-only verify that accepts an earlier release render must take this very
// file as current for the earlier image the account's protected records name,
// so a later change to the hook template cannot silently bring the failed
// Copilot row and the administrator's verify 1603 back. It is checked for the
// Local hook file and for the plugin's hooks.json, which hold the same render.
func TestGAP1898PriorReleaseVerifyAcceptsTheReleased1010LocalHookFile(t *testing.T) {
	const (
		bin     = `C:\Program Files\Cisco\DefenseClaw\bin`
		earlier = bin + `\hooks\6081ba06f39a5eb8\defenseclaw-hook.exe`
		current = bin + `\hooks\65b4297c1bc70cbd\defenseclaw-hook.exe`
	)
	released, err := os.ReadFile(filepath.Join("testdata", "copilot-vscode-1.0.10", "windows-hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The bridge starts powershell.exe from the system directory the host
	// reports, as 1.0.10 did on the computer the file was taken from.
	exe, _, _ := strings.Cut(connector.CopilotVSCodeLocalManagedHookCommand("windows", current, "Stop"), " -NoLogo")
	released = bytes.ReplaceAll(released, []byte(`C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe`),
		[]byte(strings.ReplaceAll(exe, `\`, `\\`)))

	home := t.TempDir()
	if _, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{
		Home: home, GOOS: "windows", HookBinary: earlier, HookFile: true, Plugin: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{CopilotVSCodeLocalHookFilePath(home), CopilotPluginHooksPath(home)} {
		writeFile(t, path, string(released))
	}
	verify := func(acceptPrior bool, recorded string) CopilotVSCodeUserResult {
		t.Helper()
		result, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{
			Home: home, GOOS: "windows", HookBinary: current, HookFile: true, Plugin: true,
			DryRun: true, AcceptPriorRelease: acceptPrior, RecordedHookBinary: recorded,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	if result := verify(true, earlier); len(result.Changed)+len(result.Removed)+len(result.Kept) != 0 || !result.HookFileOK || !result.PluginOK {
		t.Fatalf("prior-render verify of the 1.0.10 files with the recorded image: %+v, want both files current", result)
	}
	// Without the recorded image, or in a verify that takes no earlier render,
	// the 1.0.10 files are stale for the current image.
	for name, result := range map[string]CopilotVSCodeUserResult{
		"prior-render verify without the recorded image": verify(true, ""),
		"strict verify with the recorded image":          verify(false, earlier),
	} {
		if len(result.Changed) != 2 {
			t.Fatalf("%s: %+v, want both files stale", name, result)
		}
	}
}
