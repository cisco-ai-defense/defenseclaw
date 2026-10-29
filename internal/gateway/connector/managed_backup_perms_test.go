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
	"strconv"
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
	home := testenv.PrivateTempDir(t)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	oldRoot := home
	newRoot := testenv.PrivateTempDir(t)
	dataDir := testenv.PrivateTempDir(t)
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
	// Windows registers the native hook launcher (through the system
	// cmd.exe, GAP-1908) instead of hooks/codex-hook.sh.
	hookMarker := []byte("codex-hook")
	if runtime.GOOS == "windows" {
		hookMarker = []byte("hook --connector codex --event ")
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
	// A failed batch after the forward move asks Setup to move this same
	// registration back. The old backup must again name the enforcing root.
	t.Setenv("CODEX_HOME", oldRoot)
	t.Setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", oldRoot)
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("restore previous Codex root: %v", err)
	}
	for _, root := range []struct {
		path     string
		wantHook bool
	}{{oldRoot, true}, {newRoot, false}} {
		raw, err := os.ReadFile(filepath.Join(root.path, "config.toml"))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if got := bytes.Contains(raw, hookMarker); got != root.wantHook {
			t.Fatalf("%s hook presence after rollback = %t, want %t", root.path, got, root.wantHook)
		}
	}
	backup, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, "codex", "config.toml"))
	if err != nil {
		t.Fatalf("read restored Codex backup: %v", err)
	}
	if backup.Path != filepath.Join(oldRoot, "config.toml") {
		t.Fatalf("rollback backup path = %q, want old root", backup.Path)
	}
}

func TestCodexExplicitSetupRestoresCopiedHomeRoot(t *testing.T) {
	for _, oldHomeState := range []string{"unrelated", "empty-codex"} {
		t.Run(oldHomeState, func(t *testing.T) {
			testCodexExplicitSetupRestoresCopiedHomeRoot(t, oldHomeState)
		})
	}
}

func TestCodexCopiedHomeKeepsPopulatedOldWindowsRoot(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows launcher ownership")
	}
	oldHome := testenv.PrivateTempDir(t)
	currentHome := testenv.PrivateTempDir(t)
	t.Setenv("HOME", currentHome)
	t.Setenv("USERPROFILE", currentHome)
	oldConfig := filepath.Join(oldHome, ".codex", "config.toml")
	currentConfig := filepath.Join(currentHome, ".codex", "config.toml")
	for _, path := range []string{oldConfig, currentConfig} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	contract := builtinHookContracts["codex"][0]
	event := contract.Events[0]
	for _, item := range []struct {
		path string
		home string
	}{{oldConfig, oldHome}, {currentConfig, currentHome}} {
		launcher := filepath.Join(item.home, ".local", "bin", windowsHookBinaryName)
		command := windowsNativePowerShellHookCommandForCodexEvent(event, contract.ContractID, launcher)
		config := "[[hooks." + event + "]]\n[[hooks." + event + ".hooks]]\ncommand = " + strconv.Quote(command) + "\n"
		if err := os.WriteFile(item.path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	record := managedFileBackupPath(filepath.Join(currentHome, ".defenseclaw"), "codex", "config.toml")
	moved, err := codexBackupTargetMatchingPostHash(record, oldConfig, sha256Hex([]byte("prior installed bytes")))
	if err != nil || moved != "" {
		t.Fatalf("populated old Codex root was rebound to %q (error %v)", moved, err)
	}
}

func TestCodexCopiedHomeFindsEditedWindowsConfigBeforeRepair(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows launcher ownership")
	}
	for _, oldHomeState := range []string{"unrelated", "empty-codex"} {
		t.Run(oldHomeState, func(t *testing.T) {
			oldHome := testenv.PrivateTempDir(t)
			currentHome := testenv.PrivateTempDir(t)
			t.Setenv("HOME", currentHome)
			t.Setenv("USERPROFILE", currentHome)
			oldConfig := filepath.Join(oldHome, ".codex", "config.toml")
			currentConfig := filepath.Join(currentHome, ".codex", "config.toml")
			if err := os.MkdirAll(filepath.Dir(currentConfig), 0o700); err != nil {
				t.Fatal(err)
			}
			if oldHomeState == "empty-codex" {
				if err := os.MkdirAll(filepath.Dir(oldConfig), 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(oldHome, ".profile"), []byte("kept"), 0o600); err != nil {
				t.Fatal(err)
			}
			contract := builtinHookContracts["codex"][0]
			event := contract.Events[0]
			launcher := filepath.Join(oldHome, ".local", "bin", windowsHookBinaryName)
			command := windowsNativePowerShellHookCommandForCodexEvent(event, contract.ContractID, launcher)
			installed := "[[hooks." + event + "]]\n[[hooks." + event + ".hooks]]\ncommand = " + strconv.Quote(command) + "\n"
			if oldHomeState == "empty-codex" {
				installed = "[[hooks." + event + "]]\n[[hooks." + event + ".hooks]]\ncommand = " +
					strconv.Quote("user-owned fallback") + "\ncommand_windows = " + strconv.Quote(command) + "\n"
			}
			installedBytes := []byte(installed)
			edited := append(append([]byte(nil), installedBytes...), []byte("\n[projects.\"trusted\"]\ntrust_level = \"trusted\"\n")...)
			if err := os.WriteFile(currentConfig, edited, 0o600); err != nil {
				t.Fatal(err)
			}
			record := managedFileBackupPath(filepath.Join(currentHome, ".defenseclaw"), "codex", "config.toml")
			moved, err := codexBackupTargetMatchingPostHash(record, oldConfig, sha256Hex(installedBytes))
			if err != nil || moved != currentConfig {
				t.Fatalf("edited copied Codex config resolved to %q, want %q (error %v)", moved, currentConfig, err)
			}
		})
	}
}

func TestCodexCopiedHomeFindsEditedUnixConfigBeforeRepair(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Codex hook script")
	}
	for _, oldHomeState := range []string{"unrelated", "empty-codex"} {
		t.Run(oldHomeState, func(t *testing.T) {
			oldHome := testenv.PrivateTempDir(t)
			currentHome := testenv.PrivateTempDir(t)
			t.Setenv("HOME", currentHome)
			oldConfig := filepath.Join(oldHome, ".codex", "config.toml")
			currentConfig := filepath.Join(currentHome, ".codex", "config.toml")
			if err := os.MkdirAll(filepath.Dir(currentConfig), 0o700); err != nil {
				t.Fatal(err)
			}
			if oldHomeState == "empty-codex" {
				if err := os.MkdirAll(filepath.Dir(oldConfig), 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(oldHome, ".profile"), []byte("kept"), 0o600); err != nil {
				t.Fatal(err)
			}
			oldScript := filepath.Join(oldHome, ".defenseclaw", "hooks", "codex-hook.sh")
			installed := []byte("[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\ncommand = " +
				strconv.Quote(oldScript+" --event PreToolUse --hook-contract codex-hooks-v4") + "\n")
			edited := append(append([]byte(nil), installed...), []byte("\n[projects.\"trusted\"]\ntrust_level = \"trusted\"\n")...)
			if err := os.WriteFile(currentConfig, edited, 0o600); err != nil {
				t.Fatal(err)
			}
			record := managedFileBackupPath(filepath.Join(currentHome, ".defenseclaw"), "codex", "config.toml")
			moved, err := codexBackupTargetMatchingPostHash(record, oldConfig, sha256Hex(installed))
			if err != nil || moved != currentConfig {
				t.Fatalf("edited copied Codex config resolved to %q, want %q (error %v)", moved, currentConfig, err)
			}
		})
	}
}

func testCodexExplicitSetupRestoresCopiedHomeRoot(t *testing.T, oldHomeState string) {
	oldHome := testenv.PrivateTempDir(t)
	currentHome := oldHome + "-current"
	oldRoot := filepath.Join(oldHome, ".codex")
	currentRoot := filepath.Join(currentHome, ".codex")
	nextRoot := testenv.PrivateTempDir(t)
	oldData := filepath.Join(oldHome, ".defenseclaw")
	currentData := filepath.Join(currentHome, ".defenseclaw")
	if err := os.Rename(testenv.PrivateTempDir(t), oldRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(testenv.PrivateTempDir(t), oldData); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", oldHome)
	t.Setenv("USERPROFILE", oldHome)
	t.Setenv("CODEX_HOME", oldRoot)
	c := NewCodexConnector()
	opts := SetupOpts{DataDir: oldData, APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("initial setup: %v", err)
	}
	if err := os.Rename(oldHome, currentHome); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(oldHome)
		_ = os.Rename(currentHome, oldHome)
	})
	t.Setenv("HOME", currentHome)
	t.Setenv("USERPROFILE", currentHome)
	t.Setenv("CODEX_HOME", currentRoot)
	t.Setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", currentRoot)
	opts.DataDir = currentData
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair after home move: %v", err)
	}
	configPath := filepath.Join(currentRoot, "config.toml")
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		groups, err := codexHookGroupsForOptions(opts)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := bytes.Count(config, []byte("hook --connector codex --event ")), 2*len(groups); got != want {
			t.Fatalf("copied-home repair registered %d native hook commands, want %d", got, want)
		}
	}
	recordPath := managedFileBackupPath(currentData, "codex", "config.toml")
	preSetup, err := loadManagedFileBackupPath(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	// The copied receipt still names the prior home. An unrelated file or
	// empty .codex folder there must not make Setup move hooks back to it.
	preSetup.Path = filepath.Join(oldRoot, "config.toml")
	preSetup.PostSHA256 = sha256Hex(config)
	if err := writeManagedFileBackup(recordPath, preSetup); err != nil {
		t.Fatal(err)
	}
	configWithTrust := append(append([]byte(nil), config...), []byte(
		"\n[projects."+strconv.Quote(filepath.Join(currentHome, "trusted-project"))+"]\ntrust_level = \"trusted\"\n",
	)...)
	if err := os.WriteFile(configPath, configWithTrust, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(oldRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if oldHomeState == "unrelated" {
		if err := os.WriteFile(filepath.Join(oldHome, ".profile"), []byte("kept"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("CODEX_HOME", nextRoot)
	t.Setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", nextRoot)
	previous, err := codexPreviousSetupRoot(currentData)
	if err != nil || previous != currentRoot {
		t.Fatalf("forward move chose previous root %q, want %q (error %v)", previous, currentRoot, err)
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("forward root move: %v", err)
	}
	hookMarker := []byte("codex-hook")
	if runtime.GOOS == "windows" {
		hookMarker = []byte("hook --connector codex --event ")
	}
	forwardPrevious, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(forwardPrevious, hookMarker) {
		t.Fatal("forward root move left managed hooks in the previous Codex config")
	}
	t.Setenv("CODEX_HOME", currentRoot)
	t.Setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", currentRoot)
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("reverse root move: %v", err)
	}
	for _, item := range []struct {
		root string
		want bool
	}{{currentRoot, true}, {nextRoot, false}, {oldRoot, false}} {
		raw, err := os.ReadFile(filepath.Join(item.root, "config.toml"))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if got := bytes.Contains(raw, hookMarker); got != item.want {
			t.Fatalf("%s hook presence after rollback = %t, want %t", item.root, got, item.want)
		}
		if item.root == currentRoot && !bytes.Contains(raw, []byte("trust_level = \"trusted\"")) {
			t.Fatal("Codex's project trust edit was lost during root migration")
		}
	}
	restored, err := loadManagedFileBackupPath(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	pristineHasHooks := bytes.Contains(restored.PristineBytes, hookMarker)
	pristineHasTrust := bytes.Contains(restored.PristineBytes, []byte("trust_level = \"trusted\""))
	if restored.Path != configPath || !restored.Existed || pristineHasHooks || !pristineHasTrust {
		t.Fatalf("Codex rollback lost the current root or pristine config: path=%q existed=%v hooks=%v trust=%v",
			restored.Path, restored.Existed, pristineHasHooks, pristineHasTrust)
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

// GAP-0633: an account moved by copying its home and then emptying the old
// folder keeps the old home as an empty folder. The record follows the move
// as it does when the old home is gone; an old home that still holds a file
// does not.
func TestManagedBackupFollowsAHomeMovedIntoAnEmptiedOldHome(t *testing.T) {
	for _, tc := range []struct {
		name      string
		leftovers bool
		want      bool
	}{{"emptied", false, true}, {"not emptied", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			oldHome := filepath.Join(root, "old-home")
			newHome := filepath.Join(root, "new-home")
			oldTarget := filepath.Join(oldHome, ".config", "opencode", "plugins", "defenseclaw.js")
			newTarget := filepath.Join(newHome, ".config", "opencode", "plugins", "defenseclaw.js")
			record := filepath.Join(newHome, ".defenseclaw", "connector_backups", "opencode", "plugin.json")
			for _, dir := range []string{filepath.Dir(newTarget), filepath.Dir(record), oldHome} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(newTarget, []byte("// plugin\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.leftovers {
				if err := os.WriteFile(filepath.Join(oldHome, ".profile"), []byte("# kept\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", newHome)
			t.Setenv("USERPROFILE", newHome)
			got, ok := managedBackupTargetAfterHomeMove(record, oldTarget)
			if ok != tc.want || (tc.want && got != newTarget) {
				t.Fatalf("mapped %q (%v), want %v onto %s", got, ok, tc.want, newTarget)
			}
		})
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
	if err := captureManagedFileBackup(dataDir, "copilot", "config", target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"hooks":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateManagedFileBackupPostHash(dataDir, "copilot", "config", target); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err := restoreManagedFileBackupIfUnchanged(dataDir, "copilot", "config", target)
	if got, want := restoreBackupFailure(err), "could not restore "+target+": permission denied"; got != want {
		t.Fatalf("restore failure = %q, want %q", got, want)
	}
}
