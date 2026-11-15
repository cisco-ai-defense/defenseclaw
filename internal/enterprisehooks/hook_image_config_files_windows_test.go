//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"path/filepath"
	"strings"
	"testing"

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
	home := t.TempDir()
	const sid = "S-1-5-21-1-2-3-1018"
	enabled := true
	var targets []ManifestTarget
	for _, name := range []string{"copilot", "hermes", "kiro", "opencode", "retiredagent"} {
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
	} {
		file, ok := listed[strings.ToLower(want)]
		if !ok {
			t.Errorf("not listed: %s", want)
			continue
		}
		if !file.User || file.SID != sid || !strings.EqualFold(file.Home, home) {
			t.Errorf("%s is not the account's file: %+v", want, file)
		}
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "(retiredagent): not a connector this release knows") {
		t.Errorf("problems = %v, want only the unknown connector", problems)
	}
	if t.Failed() {
		t.Logf("listed: %+v", files)
	}
}
