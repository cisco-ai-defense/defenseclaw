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
	"unsafe"

	"golang.org/x/sys/windows"
)

// An uninstall with purge removes an account's per-user state as
// LocalSystem, per-user hook tokens included, and keeps only the account's
// moved-aside hooks and each hook script as the disabled stub, written in
// place. A junction in the folder is removed, not followed, and so is a
// subfolder whose access list denies the purge.
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
	script := filepath.Join(dataDir, "hooks", "amp-hook.sh")
	// The managed install left the kept folders and stubs with the managed
	// DACL, whose read-only OWNER RIGHTS entry denies the account WRITE_DAC.
	sid := currentWindowsTestSID(t)
	hardened := map[string]string{
		dataDir:                         windowsRelaxTestHardenedDir,
		filepath.Join(dataDir, "hooks"): windowsRelaxTestHardenedDir,
		script:                          windowsRelaxTestHardenedFile,
	}
	for path, sddl := range hardened {
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil); err != nil {
			t.Fatalf("set owner of %s: %v", path, err)
		}
		windowsRelaxTestSetDACL(t, path, windowsRelaxTestFormat(sddl, sid))
	}
	// The account can deny SYSTEM on a folder it owns; the test denies its
	// own account, which the purge runs as here.
	windowsRelaxTestSetDACL(t, filepath.Join(dataDir, "logs", "denied"), "D:P(D;OICI;FA;;;"+sid.String()+")")
	before, err := os.Stat(script)
	if err != nil {
		t.Fatal(err)
	}

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
	// What stayed goes back to a DACL the account can manage, so a later
	// per-user install can protect its own folder.
	for path := range hardened {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(sd.String(), windowsGuardianHardenedOwnerRightsACE) {
			t.Fatalf("%s kept the managed DACL after the purge: %s", path, sd)
		}
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
