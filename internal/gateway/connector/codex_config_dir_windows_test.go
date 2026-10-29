// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureCodexConfigDirWindowsCreatesTrustedMissingDirectory(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "missing", ".codex")
	if err := ensureCodexConfigDir(configDir); err != nil {
		t.Fatalf("ensureCodexConfigDir: %v", err)
	}
	if err := hookAPIValidateDirectory(configDir); err != nil {
		t.Fatalf("created Codex configuration directory is not trusted: %v", err)
	}
}

func TestEnsureCodexConfigDirWindowsRejectsReparseParent(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "codex-home")
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, outside).CombinedOutput()
	if err != nil {
		t.Skipf("junction creation unavailable: %v (%s)", err, output)
	}
	defer os.Remove(junction)

	err = ensureCodexConfigDir(filepath.Join(junction, ".codex"))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("ensureCodexConfigDir through junction error = %v, want reparse-point rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, ".codex")); !os.IsNotExist(statErr) {
		t.Fatalf("Codex directory escaped through junction: %v", statErr)
	}
}

// GAP-2339: a CODEX_HOME through a junction is refused before Setup changes
// anything (an agent-settings refusal that names the junction and the fix), not
// after it moved the hooks from the earlier home. A real folder is not refused.
func TestCodexSetupRefusesACodexHomeThroughAJunctionBeforeAnyChange(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "codex-home-junction")
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, real).CombinedOutput()
	if err != nil {
		t.Skipf("junction creation unavailable: %v (%s)", err, output)
	}
	defer os.Remove(junction)
	previous := CodexConfigPathOverride
	CodexConfigPathOverride = ""
	t.Cleanup(func() { CodexConfigPathOverride = previous })
	opts := SetupOpts{DataDir: filepath.Join(root, "data")}

	t.Setenv("CODEX_HOME", junction)
	err = (&CodexConnector{}).checkAgentSettings(opts)
	if !errors.Is(err, ErrAgentConfigRefusal) || !errors.Is(err, ErrSetupRefusedUnchanged) {
		t.Fatalf("checkAgentSettings with CODEX_HOME through a junction = %v, want an agent-settings refusal before any change", err)
	}
	for _, want := range []string{junction, "symbolic link or junction", "set CODEX_HOME to the real folder, or unset it", "then run: defenseclaw setup codex"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not name %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "defenseclaw upgrade") {
		t.Fatalf("refusal %q still points at defenseclaw upgrade", err)
	}
	if _, statErr := os.Stat(filepath.Join(real, "config.toml")); !os.IsNotExist(statErr) {
		t.Fatalf("refusal wrote through the junction: %v", statErr)
	}

	t.Setenv("CODEX_HOME", real)
	if err := (&CodexConnector{}).checkAgentSettings(opts); err != nil {
		t.Fatalf("checkAgentSettings with a real CODEX_HOME folder = %v, want nil", err)
	}
}
