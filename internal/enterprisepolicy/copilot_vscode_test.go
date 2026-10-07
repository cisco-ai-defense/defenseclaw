// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestCopilotVSCodeLocalAndManagedSettings covers the per-user Local hook
// file and plugin (written, recognized as DefenseClaw's by the guard) and
// the managed-settings keys (plugin enabled and the managed-only lock only
// while a VS Code in the plugin store window is installed, removal keeping
// the administrator's keys).
func TestCopilotVSCodeLocalAndManagedSettings(t *testing.T) {
	home := t.TempDir()
	ensure := func(hookFile, plugin bool) CopilotVSCodeUserResult {
		t.Helper()
		result, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{
			Home: home, GOOS: "linux", HookBinary: testHookBinary, HookFile: hookFile, Plugin: plugin,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := ensure(true, true); !result.HookFileOK || !result.PluginOK || len(result.Changed) != 3 {
		t.Fatalf("first placement: %+v", result)
	}
	hookFile := CopilotVSCodeLocalHookFilePath(home)
	if !(GuardRequest{GOOS: "linux", HookBinary: testHookBinary}).ownedHooksDocument([]byte(readFile(t, hookFile))) {
		t.Fatal("the guard does not recognize the Local hook file as DefenseClaw's")
	}
	if result := ensure(true, true); len(result.Changed) != 0 || !result.PluginOK {
		t.Fatalf("second placement not idempotent: %+v", result)
	}

	opts := withPolicy(testOptions(t), copilotConnector, func(p *config.EnterpriseConnectorPolicy) {
		p.ManagedHooksOnly = config.ManagedHooksOnlyEnforce
	})
	opts.CopilotUserHomes = []string{home}
	settings, err := CopilotManagedSettingsPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, settings, `{"model":"admin"}`)
	reconcile := func() string {
		t.Helper()
		if err := copilotManagedSettings(opts, &State{}, true); err != nil {
			t.Fatal(err)
		}
		return readFile(t, settings)
	}
	// No VS Code reads the plugin, and the Copilot CLI reads this file too
	// and waits on a marketplace it does not know (GAP-0192): no keys.
	if got := reconcile(); strings.Contains(got, CopilotPluginKey) || strings.Contains(got, copilotSettingHooksOnly) {
		t.Fatalf("without a VS Code in the plugin store window: %s", got)
	}
	writeFile(t, rooted(opts, "/usr/share/code/resources/app/package.json"), `{"version":"1.139.2"}`)
	if got := reconcile(); !strings.Contains(got, CopilotPluginKey) || !strings.Contains(got, copilotSettingHooksOnly) || !strings.Contains(got, `"admin"`) {
		t.Fatalf("keys not set once the gate passed: %s", got)
	}
	writeFile(t, rooted(opts, "/usr/share/code/resources/app/package.json"), `{"version":"1.141.0"}`)
	if got := reconcile(); strings.Contains(got, CopilotPluginKey) || strings.Contains(got, copilotSettingHooksOnly) || !strings.Contains(got, `"admin"`) {
		t.Fatalf("keys left after VS Code left the window: %s", got)
	}
	writeFile(t, rooted(opts, "/usr/share/code/resources/app/package.json"), `{"version":"1.139.2"}`)
	reconcile()
	if err := removeCopilotManagedSettings(opts, &State{}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, settings); strings.Contains(got, CopilotPluginKey) || strings.Contains(got, copilotSettingHooksOnly) || !strings.Contains(got, `"admin"`) {
		t.Fatalf("removal: %s", got)
	}

	ensure(false, false)
	if _, err := os.Stat(filepath.Dir(CopilotPluginDir(home))); !os.IsNotExist(err) {
		t.Fatalf("plugin directories left behind: %v", err)
	}
}

// The Local hook file is the guardian's (WIN-R1-25): verify reports a
// deleted or edited copy as drift, setup rewrites it and uninstall removes
// it, whatever the user left at its name.
func TestCopilotVSCodeRepairsATamperedHookFile(t *testing.T) {
	home := t.TempDir()
	run := func(keep, dryRun bool) CopilotVSCodeUserResult {
		t.Helper()
		result, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{
			Home: home, GOOS: "linux", HookBinary: testHookBinary, HookFile: keep, DryRun: dryRun,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	run(true, false)
	hookFile := CopilotVSCodeLocalHookFilePath(home)
	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	if result := run(true, true); len(result.Changed) != 1 {
		t.Fatalf("verify must report the deleted hook file as drift: %+v", result)
	}
	// Edited and marked read-only (0o400 sets the Windows read-only
	// attribute), which a rename alone cannot replace there.
	edited := []byte(`{"hooks":{"PreToolUse":[{"type":"command","command":"user-tool"}]}}`)
	if err := os.WriteFile(hookFile, edited, 0o400); err != nil {
		t.Fatal(err)
	}
	if result := run(true, true); len(result.Changed) != 1 || len(result.Kept) != 0 {
		t.Fatalf("verify must report the edited hook file as drift: %+v", result)
	}
	if result := run(true, false); !result.HookFileOK {
		t.Fatalf("setup must repair the edited hook file: %+v", result)
	}
	// A directory (or link) a user puts at the name is replaced too.
	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(hookFile, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if result := run(true, false); !result.HookFileOK || readFile(t, hookFile) == "" {
		t.Fatalf("setup must replace a directory at the hook file: %+v", result)
	}
	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(hookFile, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if result := run(false, false); len(result.Removed) != 1 {
		t.Fatalf("uninstall must remove whatever is at the hook file: %+v", result)
	}
	if _, err := os.Stat(hookFile); !os.IsNotExist(err) {
		t.Fatalf("hook file left behind: %v", err)
	}
}

// The guardian created ~/.copilot, ~/.copilot/hooks and
// ~/.copilot/installed-plugins for the Local files, and their removal left
// them in the home, empty. The write reports the folders it created; the
// removal given them takes out the ones still empty, and a folder that
// existed before (or now holds the user's files) stays.
func TestCopilotVSCodeRemovalTakesOutTheFoldersItCreated(t *testing.T) {
	home := t.TempDir()
	ensure := func(keep bool, removeDirs []string) CopilotVSCodeUserResult {
		t.Helper()
		result, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{
			Home: home, GOOS: "linux", HookBinary: testHookBinary, HookFile: keep, Plugin: keep, RemoveDirs: removeDirs,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	created := ensure(true, nil).CreatedDirs
	for _, want := range []string{".copilot", ".copilot/hooks", ".copilot/installed-plugins"} {
		if !containsString(created, filepath.Join(home, filepath.FromSlash(want))) {
			t.Fatalf("created %v, want it to list ~/%s", created, want)
		}
	}
	if again := ensure(true, nil).CreatedDirs; len(again) != 0 {
		t.Fatalf("a second write created nothing, reported %v", again)
	}
	ensure(false, created)
	if _, err := os.Lstat(filepath.Join(home, ".copilot")); !os.IsNotExist(err) {
		t.Fatalf("~/.copilot stayed after the removal: %v", err)
	}

	// An existing ~/.copilot is the user's: only the folders below it go.
	own := filepath.Join(home, ".copilot", "config.json")
	if err := os.MkdirAll(filepath.Dir(own), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	created = ensure(true, nil).CreatedDirs
	if containsString(created, filepath.Join(home, ".copilot")) {
		t.Fatalf("created %v lists the user's existing ~/.copilot", created)
	}
	ensure(false, append(created, filepath.Join(home, ".copilot"), "/etc", filepath.Join(home, "..")))
	entries, err := os.ReadDir(filepath.Join(home, ".copilot"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "config.json" {
		t.Fatalf("~/.copilot holds %v (%v), want only the user's config.json", entries, err)
	}
}

// GAP-2098: an uninstall's presence check finds the Windows Local hook file
// and plugin (an encoded PowerShell bridge) until they are removed, and
// never counts a user's own plugin file as DefenseClaw's.
func TestCopilotVSCodeUserFilesLeftSeesTheWindowsRender(t *testing.T) {
	home := t.TempDir()
	const hookBinary = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	left := func() bool {
		t.Helper()
		got, err := CopilotVSCodeUserFilesLeft(home, "windows", hookBinary)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if left() {
		t.Fatal("an empty home reported DefenseClaw's Copilot files")
	}
	ensure := func(hookFile, plugin bool) {
		t.Helper()
		if _, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{Home: home, GOOS: "windows", HookBinary: hookBinary, HookFile: hookFile, Plugin: plugin}); err != nil {
			t.Fatal(err)
		}
	}
	ensure(true, true)
	data, err := os.ReadFile(CopilotVSCodeLocalHookFilePath(home))
	if err != nil || !strings.Contains(string(data), "-EncodedCommand") {
		t.Fatalf("the Windows render is not the encoded bridge (%v)", err)
	}
	if !left() {
		t.Fatal("the rendered hook file and plugin were not found")
	}
	ensure(false, true)
	if !left() {
		t.Fatal("the plugin alone was not found")
	}
	ensure(false, false)
	if left() {
		t.Fatal("files reported after their removal")
	}
	own := filepath.Join(CopilotPluginDir(home), "hooks", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(own), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, []byte(`{"hooks":{"preToolUse":[{"type":"command","command":"my-own"}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if left() {
		t.Fatal("the user's own plugin file was counted as DefenseClaw's")
	}
}
