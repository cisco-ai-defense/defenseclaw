// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package nativeinstallstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureState(t *testing.T) (State, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "DefenseClaw")
	bin := filepath.Join(root, "bin")
	installer := filepath.Join(root, "installer")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(installer, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(bin, "defenseclaw.exe")
	if err := os.WriteFile(executable, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}
	state := State{
		SchemaVersion:        1,
		InstallKind:          "native-windows-exe",
		InstallScope:         "user",
		InstallRoot:          root,
		CommandDir:           bin,
		DataRoot:             filepath.Join(t.TempDir(), ".defenseclaw"),
		Runtime:              filepath.Join(root, "runtime", "python"),
		CodexHome:            filepath.Join(t.TempDir(), "codex-home"),
		ClaudeConfigDir:      filepath.Join(t.TempDir(), "claude-home"),
		CopilotHome:          filepath.Join(t.TempDir(), "copilot-home"),
		CursorHome:           filepath.Join(t.TempDir(), "cursor-home"),
		WindsurfUserHome:     filepath.Join(t.TempDir(), "windsurf-profile"),
		AntigravityConfigDir: filepath.Join(t.TempDir(), ".gemini", "config"),
		OpenCodeConfigDir:    filepath.Join(t.TempDir(), "opencode-home"),
		OmnigentConfigHome:   filepath.Join(t.TempDir(), "omnigent-home"),
		HermesHome:           filepath.Join(t.TempDir(), "hermes-home"),
	}
	state.WindsurfHooksPath = filepath.Join(
		state.WindsurfUserHome,
		".codeium",
		"windsurf",
		"hooks.json",
	)
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installer, "install-state.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return state, executable
}

func TestLoadAtAndEnvironmentRehydrateDocumentedConnectorHomes(t *testing.T) {
	want, executable := fixtureState(t)
	got, err := loadAt(executable, want.InstallRoot)
	if err != nil {
		t.Fatal(err)
	}
	env := got.Environment([]string{
		"PATH=fixture",
		"CODEX_HOME=project-codex",
		"claude_config_dir=project-claude",
		"copilot_home=project-copilot",
		"defenseclaw_cursor_config_home=project-cursor",
		"windsurf_user_home=project-windsurf",
		"windsurf_hook_config_path=project-windsurf-hooks",
		"opencode_config_dir=project-opencode",
		"omnigent_config_home=project-omnigent",
		"hermes_home=project-hermes",
		"DEFENSECLAW_HOME=project-data",
		"ANTIGRAVITY_CONFIG_DIR=project-antigravity",
		"GEMINI_CONFIG_DIR=project-gemini",
		"DEFENSECLAW_ANTIGRAVITY_CONFIG_HOME=project-internal",
	})
	joined := strings.Join(env, "\n")
	for _, expected := range []string{
		"CODEX_HOME=" + want.CodexHome,
		"CLAUDE_CONFIG_DIR=" + want.ClaudeConfigDir,
		"COPILOT_HOME=" + want.CopilotHome,
		"DEFENSECLAW_CURSOR_CONFIG_HOME=" + want.CursorHome,
		"WINDSURF_USER_HOME=" + want.WindsurfUserHome,
		"WINDSURF_HOOK_CONFIG_PATH=" + want.WindsurfHooksPath,
		"OPENCODE_CONFIG_DIR=" + want.OpenCodeConfigDir,
		"OMNIGENT_CONFIG_HOME=" + want.OmnigentConfigHome,
		"HERMES_HOME=" + want.HermesHome,
		"DEFENSECLAW_HOME=" + want.DataRoot,
		"DEFENSECLAW_INSTALL_ROOT=" + want.InstallRoot,
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("managed environment missing %q: %v", expected, env)
		}
	}
	if strings.Contains(joined, "project-") {
		t.Fatalf("ambient profile override survived: %v", env)
	}
	for _, forbidden := range []string{
		"ANTIGRAVITY_CONFIG_DIR=",
		"GEMINI_CONFIG_DIR=",
		"DEFENSECLAW_ANTIGRAVITY_CONFIG_HOME=",
	} {
		if strings.Contains(strings.ToUpper(joined), forbidden) {
			t.Fatalf("invented Antigravity config environment survived: %v", env)
		}
	}
	if got.AntigravityConfigDir != want.AntigravityConfigDir {
		t.Fatalf("internal Antigravity custody path = %q, want %q", got.AntigravityConfigDir, want.AntigravityConfigDir)
	}
}

func TestEnvironmentRemovesAmbientConnectorHomesFromLegacyState(t *testing.T) {
	state := State{InstallRoot: `C:\Program Files\DefenseClaw`, DataRoot: `C:\Users\fixture\.defenseclaw`}
	env := state.Environment([]string{
		"PATH=fixture",
		"CODEX_HOME=project-codex",
		"claude_config_dir=project-claude",
		"copilot_home=project-copilot",
		"defenseclaw_cursor_config_home=project-cursor",
		"windsurf_user_home=project-windsurf",
		"windsurf_hook_config_path=project-windsurf-hooks",
		"opencode_config_dir=project-opencode",
		"omnigent_config_home=project-omnigent",
		"hermes_home=project-hermes",
		"antigravity_config_dir=project-antigravity",
		"gemini_config_dir=project-gemini",
		"defenseclaw_antigravity_config_home=project-internal",
	})
	joined := strings.Join(env, "\n")
	if strings.Contains(strings.ToUpper(joined), "CODEX_HOME=") ||
		strings.Contains(strings.ToUpper(joined), "CLAUDE_CONFIG_DIR=") ||
		strings.Contains(strings.ToUpper(joined), "COPILOT_HOME=") ||
		strings.Contains(strings.ToUpper(joined), "DEFENSECLAW_CURSOR_CONFIG_HOME=") ||
		strings.Contains(strings.ToUpper(joined), "WINDSURF_USER_HOME=") ||
		strings.Contains(strings.ToUpper(joined), "WINDSURF_HOOK_CONFIG_PATH=") ||
		strings.Contains(strings.ToUpper(joined), "OPENCODE_CONFIG_DIR=") ||
		strings.Contains(strings.ToUpper(joined), "OMNIGENT_CONFIG_HOME=") ||
		strings.Contains(strings.ToUpper(joined), "HERMES_HOME=") ||
		strings.Contains(strings.ToUpper(joined), "ANTIGRAVITY_CONFIG_DIR=") ||
		strings.Contains(strings.ToUpper(joined), "GEMINI_CONFIG_DIR=") ||
		strings.Contains(strings.ToUpper(joined), "DEFENSECLAW_ANTIGRAVITY_CONFIG_HOME=") {
		t.Fatalf("ambient connector home survived legacy state: %v", env)
	}
}

func TestLoadAtRejectsRelocatedOrMalformedState(t *testing.T) {
	state, executable := fixtureState(t)
	state.InstallRoot = filepath.Join(t.TempDir(), "foreign")
	body, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(filepath.Dir(filepath.Dir(executable)), "installer", "install-state.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAt(executable, filepath.Dir(filepath.Dir(executable))); err == nil {
		t.Fatal("relocated state was accepted")
	}
}

func TestLoadAtRejectsMalformedWindsurfProfileBinding(t *testing.T) {
	state, executable := fixtureState(t)
	state.WindsurfUserHome = filepath.Join("relative", "profile")
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(filepath.Dir(filepath.Dir(executable)), "installer", "install-state.json")
	if err := os.WriteFile(statePath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAt(executable, filepath.Dir(filepath.Dir(executable))); err == nil {
		t.Fatal("malformed Windsurf profile binding was accepted")
	}
}
