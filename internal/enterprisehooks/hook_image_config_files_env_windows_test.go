//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-10 GAP-0885: retire runs in an administrator's shell, which may
// set an agent home for the administrator's own agents. The guardian's
// service environment sets none, so each account's files are the ones in
// its own home, never the administrator's folder.
func TestWindowsManagedHookConfigFilesIgnoresTheCallersAgentHomes(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, "")
	admin := t.TempDir()
	for _, name := range []string{"CODEX_HOME", "OPENCODE_CONFIG_DIR", "CLAUDE_CONFIG_DIR", "COPILOT_HOME", "XDG_CONFIG_HOME"} {
		t.Setenv(name, filepath.Join(admin, strings.ToLower(name)))
	}
	home := t.TempDir()
	const sid = "S-1-5-21-1-2-3-1018"
	enabled := true
	var targets []ManifestTarget
	for _, name := range []string{"codex", "opencode", "copilot"} {
		targets = append(targets, ManifestTarget{User: `HOST\std2`, UserHome: home, SID: sid, Connector: name, AgentVersion: "9.9.9", Enabled: &enabled})
	}
	files, problems := WindowsManagedHookConfigFiles(writeWindowsTestManifest(t, targets...))
	listed := map[string]bool{}
	for _, file := range files {
		if strings.HasPrefix(strings.ToLower(filepath.Clean(file.Path)), strings.ToLower(filepath.Clean(admin))) {
			t.Errorf("listed the caller's folder: %+v", file)
		}
		listed[strings.ToLower(filepath.Clean(file.Path))] = file.User
	}
	for _, want := range []string{
		filepath.Join(home, ".codex", "config.toml"),
		filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js"),
		filepath.Join(home, ".copilot", "hooks", "defenseclaw.json"),
	} {
		if user, ok := listed[strings.ToLower(want)]; !ok || !user {
			t.Errorf("%s: listed %t as an account file %t", want, ok, user)
		}
	}
	if len(problems) != 0 {
		t.Errorf("problems = %v", problems)
	}
	if got := os.Getenv("CODEX_HOME"); got != filepath.Join(admin, "codex_home") {
		t.Errorf("the caller's CODEX_HOME was not restored: %q", got)
	}
	if t.Failed() {
		t.Logf("listed: %+v", files)
	}
}
