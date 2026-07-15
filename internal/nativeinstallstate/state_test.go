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
		SchemaVersion:   1,
		InstallKind:     "native-windows-exe",
		InstallScope:    "user",
		InstallRoot:     root,
		CommandDir:      bin,
		DataRoot:        filepath.Join(t.TempDir(), ".defenseclaw"),
		Runtime:         filepath.Join(root, "runtime", "python"),
		CodexHome:       filepath.Join(t.TempDir(), "codex-home"),
		ClaudeConfigDir: filepath.Join(t.TempDir(), "claude-home"),
	}
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installer, "install-state.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return state, executable
}

func TestLoadAtAndEnvironmentRehydrateConnectorHomes(t *testing.T) {
	want, executable := fixtureState(t)
	got, err := loadAt(executable, want.InstallRoot)
	if err != nil {
		t.Fatal(err)
	}
	env := got.Environment([]string{
		"PATH=fixture",
		"CODEX_HOME=project-codex",
		"claude_config_dir=project-claude",
		"DEFENSECLAW_HOME=project-data",
	})
	joined := strings.Join(env, "\n")
	for _, expected := range []string{
		"CODEX_HOME=" + want.CodexHome,
		"CLAUDE_CONFIG_DIR=" + want.ClaudeConfigDir,
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
}

func TestEnvironmentRemovesAmbientConnectorHomesFromLegacyState(t *testing.T) {
	state := State{InstallRoot: `C:\Program Files\DefenseClaw`, DataRoot: `C:\Users\fixture\.defenseclaw`}
	env := state.Environment([]string{
		"PATH=fixture",
		"CODEX_HOME=project-codex",
		"claude_config_dir=project-claude",
	})
	joined := strings.Join(env, "\n")
	if strings.Contains(strings.ToUpper(joined), "CODEX_HOME=") ||
		strings.Contains(strings.ToUpper(joined), "CLAUDE_CONFIG_DIR=") {
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
