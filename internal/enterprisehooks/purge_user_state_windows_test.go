// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	// GAP-1567: a rolled-back enrollment keeps a copy aside beside it.
	rollbackDir := filepath.Join(home, ".defenseclaw.rollback-0123456789abcdef0123456789abcdef")
	outside := filepath.Join(t.TempDir(), "outside")
	for path, body := range map[string]string{
		filepath.Join(dataDir, "hooks", "amp-hook.sh"):                         "#!/bin/sh\n# defenseclaw-managed-hook v5\nexec forward\n",
		filepath.Join(dataDir, "hooks", ".hook-amp.token"):                     "token",
		filepath.Join(dataDir, "connector_backups", "amp", "settings.json"):    "{}",
		filepath.Join(dataDir, "foreign-hook-sessions", "record.json"):         "{}",
		filepath.Join(dataDir, "foreign-hooks-backup", "amp", "settings.json"): "{}",
		filepath.Join(dataDir, "agent_selection.json"):                         "{}",
		filepath.Join(dataDir, "logs", "denied", "secret.txt"):                 "secret",
		filepath.Join(rollbackDir, "hooks", "amp-hook.sh"):                     "kept aside",
		filepath.Join(home, ".defenseclaw.rollback-notes", "keep.txt"):         "keep",
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
	if _, err := os.Lstat(rollbackDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the purge left the rolled-back copy %s: %v", rollbackDir, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".defenseclaw.rollback-notes", "keep.txt")); err != nil {
		t.Fatalf("the purge removed a folder DefenseClaw did not name: %v", err)
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

// GAP-0773: the purge lists the managed ACP folder of an account whose own
// `enterprise acp setup` run created it (the account owns it), signed out,
// revoked or ACP-only alike; a per-user install's folder stays.
func TestWindowsManagedACPUserCopiesListsAccountOwnedManagedFolders(t *testing.T) {
	previousSubkeys, previousPath := windowsProfileListSubkeyReader, windowsProfileImagePathReader
	t.Cleanup(func() { windowsProfileListSubkeyReader, windowsProfileImagePathReader = previousSubkeys, previousPath })
	sid := currentWindowsTestSID(t)
	for _, tc := range []struct {
		name  string
		files []string
		want  bool
	}{
		{"managed token copy and lock", []string{"zed-hermes.token", "zed-hermes.contract-lock.json"}, true},
		{"locks of a revoked enrollment", []string{"jetbrains-kiro.contract-lock.json"}, true},
		{"per-user install", []string{".token", "zed-hermes.contract-lock.json"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "home")
			acpDir := filepath.Join(home, ".defenseclaw", "acp")
			if err := os.MkdirAll(acpDir, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range tc.files {
				if err := os.WriteFile(filepath.Join(acpDir, name), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// The account's own setup run owns the folder; an elevated test
			// session would otherwise give it to Administrators.
			if err := windows.SetNamedSecurityInfo(acpDir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			windowsProfileListSubkeyReader = func() ([]string, error) { return []string{sid.String()}, nil }
			windowsProfileImagePathReader = func(string) (string, error) { return home, nil }
			copies, err := WindowsManagedACPUserCopies()
			if err != nil {
				t.Fatal(err)
			}
			if got := len(copies) == 1 && copies[0].Home == home; got != tc.want {
				t.Fatalf("copies = %+v, want listed %t", copies, tc.want)
			}
		})
	}
}

// GAP-1256: a standard user who makes their .defenseclaw a junction to
// another account's gets that profile listed for the ACP purge, and the
// purge, which runs as LocalSystem, refuses it and leaves the other
// account's acp folder as found.
func TestPurgeWindowsACPUserStateRefusesJunctionedDataDir(t *testing.T) {
	previousCheck := windowsEnterpriseMutationIdentityCheck
	previousSubkeys, previousPath := windowsProfileListSubkeyReader, windowsProfileImagePathReader
	t.Cleanup(func() {
		windowsEnterpriseMutationIdentityCheck = previousCheck
		windowsProfileListSubkeyReader, windowsProfileImagePathReader = previousSubkeys, previousPath
	})
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	sid := currentWindowsTestSID(t)
	home := filepath.Join(t.TempDir(), "home")
	other := filepath.Join(t.TempDir(), "other", ".defenseclaw")
	token := filepath.Join(other, "acp", "zed-hermes.token")
	if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", filepath.Join(home, ".defenseclaw"), other).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, output)
	}
	windowsProfileListSubkeyReader = func() ([]string, error) { return []string{sid.String()}, nil }
	windowsProfileImagePathReader = func(string) (string, error) { return home, nil }
	copies, err := WindowsManagedACPUserCopies()
	if err != nil || len(copies) != 1 || copies[0].Home != home {
		t.Fatalf("copies = %+v, %v; want the junctioned profile listed for a refusal", copies, err)
	}
	if err := PurgeWindowsACPUserState(home, sid.String()); err == nil || !strings.Contains(err.Error(), "link or junction") {
		t.Fatalf("purge through a junctioned .defenseclaw = %v, want a refusal", err)
	}
	if _, err := os.Stat(token); err != nil {
		t.Fatalf("the purge followed the junction and removed %s: %v", token, err)
	}
}
