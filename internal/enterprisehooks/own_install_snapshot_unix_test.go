// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

type ownInstallTestFile struct {
	body string
	mode os.FileMode
}

func writeOwnInstallTestFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func ownInstallTestSHA(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func requireOwnInstallFiles(t *testing.T, files map[string]ownInstallTestFile) {
	t.Helper()
	for path, want := range files {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("%s is gone: %v", path, err)
		}
		got, _ := os.ReadFile(path)
		if string(got) != want.body || info.Mode().Perm() != want.mode {
			t.Fatalf("%s = %q mode %o, want %q mode %o", path, got, info.Mode().Perm(), want.body, want.mode)
		}
	}
}

// ownInstallTestHome is an account with its own per-user install that set
// up Hermes: the install's hook files, contract lock, session cache and the
// backup record of ~/.hermes/config.yaml, which holds the install's hooks.
func ownInstallTestHome(t *testing.T) (home, dataDir, hermesConfig, pristine string, files map[string]ownInstallTestFile) {
	t.Helper()
	home = newTestHome(t)
	dataDir = filepath.Join(home, ".defenseclaw")
	hermesConfig = filepath.Join(home, ".hermes", "config.yaml")
	pristine = "model:\n  provider: bedrock\n"
	record, err := json.Marshal(map[string]any{
		"version": 1, "connector": "hermes", "logical_name": "config.yaml", "path": hermesConfig,
		"existed": true, "mode": 0o664, "pristine_sha256": ownInstallTestSHA(pristine),
		"pristine_bytes": []byte(pristine), "captured_at": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	files = map[string]ownInstallTestFile{
		filepath.Join(dataDir, "config.yaml"):                                     {"gateway: {}\n", 0o600},
		filepath.Join(dataDir, "hooks", "hermes-hook.sh"):                         {"#!/bin/sh\n# own hermes hook\n", 0o700},
		filepath.Join(dataDir, "hooks", "claude-code-hook.sh"):                    {"#!/bin/sh\n# defenseclaw-managed-hook v1\n# own\n", 0o700},
		filepath.Join(dataDir, "hooks", ".hookcfg"):                               {"own-hookcfg\n", 0o600},
		filepath.Join(dataDir, "hook_contract_lock.json"):                         {`{"own":true}`, 0o600},
		filepath.Join(dataDir, "hermes-home-setup.json"):                          {`{"home":"own"}`, 0o600},
		filepath.Join(dataDir, "session-facts.json"):                              {`{"facts":"own"}`, 0o600},
		filepath.Join(dataDir, "connector_backups", "hermes", "config.yaml.json"): {string(record), 0o600},
		hermesConfig: {pristine + "hooks:\n  pre_tool_call: own\n", 0o600},
	}
	for path, file := range files {
		writeOwnInstallTestFile(t, path, file.body, file.mode)
	}
	return home, dataDir, hermesConfig, pristine, files
}

// rel-1-0-6 GAP-0178: the enrollment rewrites the own install's hook files
// and contract lock, writes the Claude Code blocker, adds its own hook
// token and Hermes state, and its uninstall reverts ~/.hermes/config.yaml to
// the content from before the own install and deletes that install's backup
// record. The put-back leaves every own install file, and that agent
// config, byte for byte and mode for mode as before the enrollment, and
// nothing the enrollment added.
func TestRestoreOwnInstallPutsTheOwnInstallBackByteForByte(t *testing.T) {
	skipIfRoot(t)
	home, dataDir, hermesConfig, pristine, files := ownInstallTestHome(t)
	if err := PreserveOwnInstall(home, dataDir); err != nil {
		t.Fatalf("PreserveOwnInstall: %v", err)
	}
	// What the enrollment and its uninstall do to the folder.
	writeOwnInstallTestFile(t, filepath.Join(dataDir, "hooks", "hermes-hook.sh"), "#!/bin/sh\n# managed\n", 0o700)
	writeOwnInstallTestFile(t, filepath.Join(dataDir, "hooks", "claude-code-hook.sh"), PersonalClaudeHookBlocker, 0o700)
	writeOwnInstallTestFile(t, filepath.Join(dataDir, "hooks", ".hook-hermes.token"), "managed-token\n", 0o600)
	writeOwnInstallTestFile(t, filepath.Join(dataDir, "hook_contract_lock.json"), `{"managed":true}`, 0o600)
	writeOwnInstallTestFile(t, filepath.Join(dataDir, "removed-connectors-logged.json"), `{}`, 0o600)
	writeOwnInstallTestFile(t, filepath.Join(dataDir, "connector_backups", "codex", "config.toml.json"), `{}`, 0o600)
	if err := os.RemoveAll(filepath.Join(dataDir, "connector_backups", "hermes")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dataDir, "session-facts.json")); err != nil {
		t.Fatal(err)
	}
	writeOwnInstallTestFile(t, hermesConfig, pristine, 0o664)

	restored, changed, err := RestoreOwnInstall(home, dataDir)
	if err != nil || !restored || len(changed) != 0 {
		t.Fatalf("RestoreOwnInstall = %t, %v, %v", restored, changed, err)
	}
	requireOwnInstallFiles(t, files)
	for _, added := range []string{
		filepath.Join(dataDir, "hooks", ".hook-hermes.token"),
		filepath.Join(dataDir, "removed-connectors-logged.json"),
		filepath.Join(dataDir, "connector_backups", "codex"),
		filepath.Join(dataDir, OwnInstallSnapshotName),
	} {
		if _, err := os.Lstat(added); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s stays after the put-back: %v", added, err)
		}
	}
	if restored, _, err := RestoreOwnInstall(home, dataDir); restored || err != nil {
		t.Fatalf("a second put-back = %t, %v; want nothing to do", restored, err)
	}
}

// An agent config that changed while the computer was managed (the managed
// uninstall did not leave its pristine content) stays as it is and is
// named; the DefenseClaw files still come back.
func TestRestoreOwnInstallKeepsAnAgentConfigChangedWhileManaged(t *testing.T) {
	skipIfRoot(t)
	home, dataDir, hermesConfig, _, files := ownInstallTestHome(t)
	if err := PreserveOwnInstall(home, dataDir); err != nil {
		t.Fatal(err)
	}
	writeOwnInstallTestFile(t, filepath.Join(dataDir, "hooks", "hermes-hook.sh"), "#!/bin/sh\n# managed\n", 0o700)
	edited := "model:\n  provider: edited-while-managed\n"
	writeOwnInstallTestFile(t, hermesConfig, edited, 0o600)
	restored, changed, err := RestoreOwnInstall(home, dataDir)
	if err != nil || !restored || len(changed) != 1 || changed[0] != hermesConfig {
		t.Fatalf("RestoreOwnInstall = %t, %v, %v; want the edited config named", restored, changed, err)
	}
	if got, _ := os.ReadFile(hermesConfig); string(got) != edited {
		t.Fatalf("the put-back replaced an agent config edited while managed: %q", got)
	}
	delete(files, hermesConfig)
	requireOwnInstallFiles(t, files)
}

// A folder without an own install gets no snapshot, and a hook script that
// already is the enrollment's blocker is never kept or put back.
func TestPreserveOwnInstallSkipsAFolderWithoutAnOwnInstallAndTheBlocker(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	writeOwnInstallTestFile(t, filepath.Join(dataDir, "hooks", "claude-code-hook.sh"), PersonalClaudeHookBlocker, 0o700)
	if err := PreserveOwnInstall(home, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, OwnInstallSnapshotName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a folder without an own install got a snapshot: %v", err)
	}
	writeOwnInstallTestFile(t, filepath.Join(dataDir, "config.yaml"), "gateway: {}\n", 0o600)
	if err := PreserveOwnInstall(home, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dataDir, "hooks", "claude-code-hook.sh")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RestoreOwnInstall(home, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "hooks", "claude-code-hook.sh")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the put-back wrote the blocker back: %v", err)
	}
}

// The blocker's unblock puts the account's own hook script back from the
// copy the enrollment kept, bytes and mode.
func TestUnblockPersonalClaudeHookPutsTheOwnScriptBack(t *testing.T) {
	skipIfRoot(t)
	dataDir := filepath.Join(newTestHome(t), ".defenseclaw")
	own := "#!/bin/sh\n# defenseclaw-managed-hook v1\n# own script\n"
	script := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	writeOwnInstallTestFile(t, filepath.Join(dataDir, PersonalClaudeHookCopyName), own, 0o750)
	writeOwnInstallTestFile(t, script, PersonalClaudeHookBlocker, 0o700)
	removed, restored, err := UnblockPersonalClaudeHook(dataDir)
	if err != nil || !removed || !restored {
		t.Fatalf("UnblockPersonalClaudeHook = %t, %t, %v", removed, restored, err)
	}
	requireOwnInstallFiles(t, map[string]ownInstallTestFile{script: {own, 0o750}})
	if _, err := os.Lstat(filepath.Join(dataDir, PersonalClaudeHookCopyName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the copy stays: %v", err)
	}
}

// rel-1-0-6 GAP-0178: the purge of an account whose folder holds its own
// per-user install tears none of that install's connectors down: its agent
// configs and backup records stay byte for byte.
func TestPurgeUserStateLeavesTheOwnInstallConnectorsAlone(t *testing.T) {
	skipIfRoot(t)
	home, dataDir, hermesConfig, _, files := ownInstallTestHome(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	body := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + filepath.Join(dataDir, "hooks", "claude-code-hook.sh") + `"}]}]}}`
	record, err := json.Marshal(map[string]any{
		"version": 1, "connector": "claudecode", "logical_name": "settings.json", "path": settings,
		"existed": false, "pristine_sha256": "missing", "post_sha256": ownInstallTestSHA(body),
		"captured_at": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	files[settings] = ownInstallTestFile{body, 0o600}
	files[filepath.Join(dataDir, "connector_backups", "claudecode", "settings.json.json")] = ownInstallTestFile{string(record), 0o600}
	for path, file := range files {
		writeOwnInstallTestFile(t, path, file.body, file.mode)
	}
	summary, err := PurgeUserState(context.Background(), InstallOptions{
		UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry(),
	})
	if err != nil || !summary.Kept || summary.Data {
		t.Fatalf("PurgeUserState = %+v, %v; want the own install kept", summary, err)
	}
	_ = hermesConfig
	requireOwnInstallFiles(t, files)
}
