// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestWriteManagedFileBackup_DirIs0o700 (M-5) verifies the per-connector
// backup dir under ${data_dir}/connector_backups/<connector>/ is owner-
// only. Listing the connector_backups tree leaks which connectors are
// installed; the payload itself already has 0o600 from atomicWriteFile,
// but a 0o755 parent dir was the historical default (MkdirAll's
// argument, not a security choice).
func TestWriteManagedFileBackup_DirIs0o700(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	target := filepath.Join(tmp, "agent.json")
	if err := os.WriteFile(target, []byte(`{"hello":"world"}`), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}

	if err := captureManagedFileBackup(tmp, "claudecode", "config", target); err != nil {
		t.Fatalf("captureManagedFileBackup: %v", err)
	}

	dir := filepath.Join(tmp, "connector_backups", "claudecode")
	testenv.AssertPrivateDirectory(t, dir)
}

func TestCodexExplicitSetupMovesRememberedRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	oldRoot := filepath.Join(home, ".codex")
	newRoot := filepath.Join(home, "dotfiles", "codex")
	dataDir := filepath.Join(home, ".defenseclaw")
	t.Setenv("CODEX_HOME", oldRoot)
	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", newRoot)
	t.Setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", newRoot)
	if notes := PinConnectorConfigRootsToSetup(dataDir); len(notes) != 0 {
		t.Fatalf("explicit setup was pinned to the old root: %q", notes)
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	// Windows registers the native hook launcher through an encoded
	// PowerShell command instead of hooks/codex-hook.sh.
	hookMarker := []byte("codex-hook")
	if runtime.GOOS == "windows" {
		hookMarker = []byte("-EncodedCommand")
	}
	for _, root := range []struct {
		path     string
		wantHook bool
	}{{oldRoot, false}, {newRoot, true}} {
		raw, err := os.ReadFile(filepath.Join(root.path, "config.toml"))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if got := bytes.Contains(raw, hookMarker); got != root.wantHook {
			t.Fatalf("%s hook presence = %t, want %t", root.path, got, root.wantHook)
		}
	}
	t.Setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", "")
	t.Setenv("CODEX_HOME", oldRoot)
	if notes := PinConnectorConfigRootsToSetup(dataDir); len(notes) != 1 || !strings.Contains(notes[0], "To move them") {
		t.Fatalf("gateway root note = %q", notes)
	}
	if got := codexHomeDir(); got != newRoot {
		t.Fatalf("gateway root = %q, want %q", got, newRoot)
	}
}

func TestEnsureManagedBackupDirRestricted_TightensExistingDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		t.Fatalf("chmod 0o755: %v", err)
	}
	if err := ensureManagedBackupDirRestricted(tmp); err != nil {
		t.Fatalf("ensureManagedBackupDirRestricted: %v", err)
	}
	testenv.AssertPrivateDirectory(t, tmp)
}

// The rollback of a failed first Windows install puts back every agent file
// setup recorded: the captured bytes, or no file when setup created it. A
// file changed since DefenseClaw wrote it, or outside the account's home,
// stays.
func TestRestoreManagedFileBackupsPutsBackWhatSetupFound(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	patched := filepath.Join(home, ".gemini", "hooks.json")
	created := filepath.Join(home, "plugins", "defenseclaw.ts")
	edited := filepath.Join(home, "hermes", "config.yaml")
	outside := filepath.Join(t.TempDir(), "config.json")
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	write(patched, "{}\n")
	write(edited, "a: 1\n")
	write(outside, "{}\n")
	if err := os.MkdirAll(filepath.Dir(created), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ connector, logical, path, body string }{
		{"antigravity", "hooks.json", patched, `{"defenseclaw-antigravity-stop":{}}`},
		{"amp", "config", created, "// defenseclaw-managed-plugin v1\n"},
		{"hermes", "config.yaml", edited, "a: 1\nhooks: {}\n"},
		{"devin", "config", outside, `{"hooks":{}}`},
	} {
		if err := captureManagedFileBackup(dataDir, item.connector, item.logical, item.path); err != nil {
			t.Fatal(err)
		}
		write(item.path, item.body)
		if err := updateManagedFileBackupPostHash(dataDir, item.connector, item.logical, item.path); err != nil {
			t.Fatal(err)
		}
	}
	write(edited, "a: 2\n")

	restored, kept, err := RestoreManagedFileBackups(dataDir, home)
	if err != nil {
		t.Fatalf("RestoreManagedFileBackups: %v", err)
	}
	if len(restored) != 2 || len(kept) != 2 {
		t.Fatalf("restored=%v kept=%v, want the patched and created files restored", restored, kept)
	}
	if got := read(patched); got != "{}\n" {
		t.Fatalf("patched file = %q, want its captured bytes", got)
	}
	if _, err := os.Lstat(created); !os.IsNotExist(err) {
		t.Fatalf("a file setup created must be removed: %v", err)
	}
	if got := read(edited); got != "a: 2\n" {
		t.Fatalf("a file changed after setup must stay: %q", got)
	}
	if got := read(outside); got != `{"hooks":{}}` {
		t.Fatalf("a file outside home must stay: %q", got)
	}
	if _, err := os.Lstat(managedFileBackupPath(dataDir, "antigravity", "hooks.json")); !os.IsNotExist(err) {
		t.Fatalf("a restored backup record must be consumed: %v", err)
	}
}

// A restore the target's directory refuses names the target and the cause
// once, not the rename twice with the staged temp file (#1032).
func TestRestoreFailureNamesTheTargetAndCauseOnce(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory the test user cannot write")
	}
	dataDir, dir := t.TempDir(), t.TempDir()
	target := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := captureManagedFileBackup(dataDir, "openhands", "config", target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"hooks":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateManagedFileBackupPostHash(dataDir, "openhands", "config", target); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err := restoreManagedFileBackupIfUnchanged(dataDir, "openhands", "config", target)
	if got, want := restoreBackupFailure(err), "could not restore "+target+": permission denied"; got != want {
		t.Fatalf("restore failure = %q, want %q", got, want)
	}
}

// GAP-0543: after the account home moved (usermod -l -d -m), the record names
// the old home. Setup must rebind it to the same file under the new home
// instead of stopping at "managed backup target mismatch", and teardown must
// then restore the file under the new home.
func TestManagedBackupFollowsAMovedHome(t *testing.T) {
	root := t.TempDir()
	oldHome := filepath.Join(root, "old-home")
	newHome := filepath.Join(root, "new-home")
	for _, dir := range []string{filepath.Join(oldHome, ".claude"), filepath.Join(oldHome, ".defenseclaw")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", oldHome)
	t.Setenv("USERPROFILE", oldHome)
	oldTarget := filepath.Join(oldHome, ".claude", "settings.json")
	if err := os.WriteFile(oldTarget, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := captureManagedFileBackup(filepath.Join(oldHome, ".defenseclaw"), "claudecode", "settings.json", oldTarget); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(oldHome, newHome); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", newHome)
	t.Setenv("USERPROFILE", newHome)
	dataDir := filepath.Join(newHome, ".defenseclaw")
	newTarget := filepath.Join(newHome, ".claude", "settings.json")

	if err := captureManagedFileBackup(dataDir, "claudecode", "settings.json", newTarget); err != nil {
		t.Fatalf("setup after a home move: %v", err)
	}
	restored, err := restoreManagedFileBackupIfUnchanged(dataDir, "claudecode", "settings.json", newTarget)
	if err != nil || !restored {
		t.Fatalf("teardown after a home move: restored=%v err=%v", restored, err)
	}
}

// GAP-0433: a gateway started with CLAUDE_CONFIG_DIR pointing elsewhere keeps
// the config root setup bound, so connector setup does not stop at "managed
// backup target mismatch".
func TestPinConnectorConfigRootsToSetup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dataDir := filepath.Join(home, ".defenseclaw")
	target := filepath.Join(home, ".claude", "settings.json")
	for _, dir := range []string{filepath.Dir(target), dataDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := captureManagedFileBackup(dataDir, "claudecode", "settings.json", target); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "alt"))
	if notes := PinConnectorConfigRootsToSetup(dataDir); len(notes) != 1 {
		t.Fatalf("notes = %q, want one", notes)
	}
	if got := claudeCodeSettingsPath(); got != target {
		t.Fatalf("settings path after the pin = %q, want %q", got, target)
	}
	if err := captureManagedFileBackup(dataDir, "claudecode", "settings.json", claudeCodeSettingsPath()); err != nil {
		t.Fatalf("setup after the pin: %v", err)
	}
}

func TestPinCodexConfigRootToSetup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dataDir := filepath.Join(home, ".defenseclaw")
	target := filepath.Join(home, "codex-alt", "config.toml")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := captureManagedFileBackup(dataDir, "codex", "config.toml", target); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	if notes := PinConnectorConfigRootsToSetup(dataDir); len(notes) != 1 {
		t.Fatalf("Codex home pin notes = %q, want one", notes)
	}
	if got := codexConfigPath(); got != target {
		t.Fatalf("Codex config after pin = %q, want %q", got, target)
	}
}
