// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// An uninstall with purge removes an account's whole per-user folder as
// LocalSystem: hook scripts, per-user hook tokens and the account's
// moved-aside hooks included. A junction in the folder is removed, not
// followed, and so is a subfolder whose access list denies the purge.
func TestPurgeWindowsUserStateRemovesEverything(t *testing.T) {
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
		filepath.Join(dataDir, "logs", "denied", "secret.txt"):                 "secret",
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
	sid := currentWindowsTestSID(t)
	// The account can deny SYSTEM on a folder it owns; the test denies its
	// own account, which the purge runs as here.
	windowsRelaxTestSetDACL(t, filepath.Join(dataDir, "logs", "denied"), "D:P(D;OICI;FA;;;"+sid.String()+")")
	if err := PurgeWindowsUserState(home, target, ""); err == nil {
		t.Fatal("the purge ran without LocalSystem")
	}
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	// LocalSystem holds SeBackupPrivilege and SeRestorePrivilege disabled,
	// so the purge must enable them itself to get past the denying
	// subfolder. An elevated test session may hold them enabled already.
	disableWindowsProcessPrivilegesForTest(t, "SeBackupPrivilege", "SeRestorePrivilege")
	if err := PurgeWindowsUserState(home, target, ""); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(dataDir); !errors.Is(err, os.ErrNotExist) {
		entries, _ := os.ReadDir(dataDir)
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("the purge left %s: %v %v", dataDir, err, names)
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "keep.txt" {
		t.Fatalf("the purge followed the junction: %s holds %v", outside, entries)
	}
}

// disableWindowsProcessPrivilegesForTest disables the named privileges in
// the process token until the test ends.
func disableWindowsProcessPrivilegesForTest(t *testing.T, names ...string) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { token.Close() })
	for _, name := range names {
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
			t.Fatal(err)
		}
		disable := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid}}}
		var previous windows.Tokenprivileges
		var size uint32
		if err := windows.AdjustTokenPrivileges(token, false, &disable, uint32(unsafe.Sizeof(previous)), &previous, &size); err != nil {
			t.Fatalf("disable %s: %v", name, err)
		}
		t.Cleanup(func() { _ = windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil) })
	}
}
