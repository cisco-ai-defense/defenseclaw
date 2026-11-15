//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-10 GAP-0880: hook-image retire and prune list the account files in
// an administrator's or SYSTEM shell, which carries no standalone profile
// pin. The list then knew only Codex, Claude Code, Cursor and Copilot, read
// no Hermes, Kiro or OpenCode account file, and missed the Copilot Local
// hook file, the Copilot plugin hooks and the Hermes allowlist, which name
// the hook too. Retire ended ok over a signed-out account whose Copilot and
// Hermes files named a launch folder, and the 1.0.9 guardian failed both.
func TestWindowsManagedHookConfigFilesListsEveryStandaloneConnectorAndItsCompanions(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	t.Setenv("HERMES_HOME", "")
	if windowsEnterpriseStandaloneProcess() {
		t.Fatal("the test process carries the standalone profile")
	}
	// A signed-in account whose Hermes home is the profile default.
	t.Cleanup(hermespath.OverrideAccountHomeForTest(nil))
	home := t.TempDir()
	const sid = "S-1-5-21-1-2-3-1018"
	enabled := true
	var targets []ManifestTarget
	for _, name := range []string{"copilot", "hermes", "kiro", "opencode", "antigravity", "devin", "amp", "retiredagent"} {
		targets = append(targets, ManifestTarget{User: `HOST\std2`, UserHome: home, SID: sid, Connector: name, AgentVersion: "1.0.0", Enabled: &enabled})
	}
	files, problems := WindowsManagedHookConfigFiles(writeWindowsTestManifest(t, targets...))
	listed := map[string]WindowsHookConfigFile{}
	for _, file := range files {
		listed[strings.ToLower(filepath.Clean(file.Path))] = file
	}
	for _, want := range []string{
		filepath.Join(home, ".copilot", "hooks", "defenseclaw.json"),
		filepath.Join(home, ".copilot", "hooks", "defenseclaw-vscode.json"),
		filepath.Join(home, ".copilot", "installed-plugins", "defenseclaw", "defenseclaw", "hooks", "hooks.json"),
		filepath.Join(home, "AppData", "Local", "hermes", "config.yaml"),
		filepath.Join(home, "AppData", "Local", "hermes", "shell-hooks-allowlist.json"),
		filepath.Join(home, ".kiro", "agents", "defenseclaw.json"),
		filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js"),
		filepath.Join(home, ".gemini", "config", "hooks.json"),
		filepath.Join(home, "AppData", "Roaming", "devin", "config.json"),
		filepath.Join(home, ".config", "amp", "plugins", "defenseclaw.ts"),
	} {
		file, ok := listed[strings.ToLower(want)]
		if !ok {
			t.Errorf("not listed: %s", want)
			continue
		}
		if !file.User || file.SID != sid || !strings.EqualFold(file.Home, home) || file.Unverified != "" {
			t.Errorf("%s is not the account's readable file: %+v", want, file)
		}
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "(retiredagent): not a connector this release knows") {
		t.Errorf("problems = %v, want only the unknown connector", problems)
	}
	if t.Failed() {
		t.Logf("listed: %+v", files)
	}
}

// rel-1-0-10 GAP-0884: a signed-out account's registry hive is not loaded, so
// its HERMES_HOME cannot be read and the profile default proves nothing (a
// moved Hermes home kept naming the launch folder and retire ended ok). The
// account's Hermes files are one unverified entry; nothing is read at the
// default.
func TestWindowsManagedHookConfigFilesSignedOutHermesIsUnverified(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, "")
	t.Cleanup(hermespath.OverrideAccountHomeForTest(func(string) (string, error) {
		return "", hermespath.ErrAccountSignedOut
	}))
	home := t.TempDir()
	const sid = "S-1-5-21-1-2-3-1018"
	enabled := true
	files, problems := WindowsManagedHookConfigFiles(writeWindowsTestManifest(t,
		ManifestTarget{User: `HOST\std2`, UserHome: home, SID: sid, Connector: "hermes", AgentVersion: "1.0.0", Enabled: &enabled}))
	if len(problems) != 0 || len(files) != 1 {
		t.Fatalf("files %+v problems %v, want one unverified Hermes entry", files, problems)
	}
	file := files[0]
	if !file.User || file.SID != sid || !strings.EqualFold(file.Home, home) ||
		!strings.Contains(file.Unverified, "signed out, Hermes home not resolvable") ||
		!strings.EqualFold(file.Path, filepath.Join(home, "AppData", "Local", "hermes", "config.yaml")) {
		t.Fatalf("signed-out Hermes entry = %+v", file)
	}
}

// turev #4: an agent home the account moved out of its profile (a Hermes
// home on another folder) is the account's, never a machine file: it is
// listed as the account's file, unverified (not read as SYSTEM).
func TestWindowsManagedHookConfigFilesMovedHomeIsAnUnverifiedAccountFile(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, "")
	moved := filepath.Join(t.TempDir(), "hermes")
	t.Cleanup(hermespath.OverrideAccountHomeForTest(func(string) (string, error) { return moved, nil }))
	home := t.TempDir()
	const sid = "S-1-5-21-1-2-3-1018"
	enabled := true
	files, problems := WindowsManagedHookConfigFiles(writeWindowsTestManifest(t,
		ManifestTarget{User: `HOST\std2`, UserHome: home, SID: sid, Connector: "hermes", AgentVersion: "1.0.0", Enabled: &enabled}))
	if len(problems) != 0 || len(files) == 0 {
		t.Fatalf("files %+v problems %v", files, problems)
	}
	for _, file := range files {
		if !file.User || file.SID != sid || !strings.Contains(file.Unverified, "outside the account home") {
			t.Errorf("moved Hermes file is not an unverified account file: %+v", file)
		}
	}
	if !strings.EqualFold(files[0].Path, filepath.Join(moved, "config.yaml")) {
		t.Errorf("first entry = %+v, want the moved config.yaml", files[0])
	}
}
