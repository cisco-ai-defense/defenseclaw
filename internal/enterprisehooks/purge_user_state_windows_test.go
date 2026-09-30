// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// An uninstall with purge removes an account's per-user state as
// LocalSystem, per-user hook tokens included, and keeps only the account's
// moved-aside hooks and each hook script as the disabled stub, written in
// place. A junction in the folder is removed, not followed.
func TestPurgeWindowsUserStateKeepsOnlyStubsAndMovedAsideHooks(t *testing.T) {
	original := windowsEnterpriseMutationIdentityCheck
	t.Cleanup(func() { windowsEnterpriseMutationIdentityCheck = original })
	windowsEnterpriseMutationIdentityCheck = func() error { return errors.New("not LocalSystem") }

	target := currentWindowsTestSID(t).String()
	home := filepath.Join(t.TempDir(), "home")
	dataDir := filepath.Join(home, ".defenseclaw")
	outside := filepath.Join(t.TempDir(), "outside")
	for path, body := range map[string]string{
		filepath.Join(dataDir, "hooks", "amp-hook.sh"):                         "#!/bin/sh\n# defenseclaw-managed-hook v5\nexec forward\n",
		filepath.Join(dataDir, "hooks", ".hook-amp.token"):                     "token",
		filepath.Join(dataDir, "connector_backups", "amp", "settings.json"):    "{}",
		filepath.Join(dataDir, "foreign-hook-sessions", "record.json"):         "{}",
		filepath.Join(dataDir, "foreign-hooks-backup", "amp", "settings.json"): "{}",
		filepath.Join(dataDir, "agent_selection.json"):                         "{}",
		filepath.Join(outside, "keep.txt"):                                     "keep",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", filepath.Join(dataDir, "link"), outside).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, output)
	}
	script := filepath.Join(dataDir, "hooks", "amp-hook.sh")
	before, err := os.Stat(script)
	if err != nil {
		t.Fatal(err)
	}

	if err := PurgeWindowsUserState(home, target, ""); err == nil {
		t.Fatal("the purge ran without LocalSystem")
	}
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	if err := PurgeWindowsUserState(home, target, ""); err != nil {
		t.Fatal(err)
	}

	for dir, want := range map[string][]string{
		dataDir:                         {"foreign-hooks-backup", "hooks"},
		filepath.Join(dataDir, "hooks"): {"amp-hook.sh"},
		outside:                         {"keep.txt"},
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		if !slices.Equal(names, want) {
			t.Fatalf("%s holds %v, want %v", dir, names, want)
		}
	}
	after, err := os.Stat(script)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !strings.Contains(string(body), "disabled tombstone") || strings.Contains(string(body), "exec forward") {
		t.Fatalf("hook script was not stubbed in place (same file %t):\n%s", os.SameFile(before, after), body)
	}
}
