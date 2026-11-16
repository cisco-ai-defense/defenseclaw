// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A teardown may leave an edited plugin and its recovery receipt. The
// standalone purge must keep both until the account resolves the edit.
func TestPurgeWindowsUserStateKeepsConnectorBackup(t *testing.T) {
	previous := windowsEnterpriseMutationIdentityCheck
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	t.Cleanup(func() { windowsEnterpriseMutationIdentityCheck = previous })

	home := filepath.Join(t.TempDir(), "home")
	dataDir := filepath.Join(home, ".defenseclaw")
	plugin := filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js")
	receipt := filepath.Join(dataDir, "connector_backups", "opencode", "config.json")
	for _, path := range []string{plugin, receipt} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	edited := []byte("// edited OpenCode plugin\n")
	if err := os.WriteFile(plugin, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	backup, err := json.Marshal(map[string]any{
		"version": 1, "connector": "opencode", "logical_name": "config",
		"path": plugin, "pristine_sha256": "missing",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receipt, backup, 0o600); err != nil {
		t.Fatal(err)
	}
	purge := func() error { return PurgeWindowsUserState(home, currentWindowsTestSID(t).String(), "") }
	if err := purge(); err == nil || !strings.Contains(err.Error(), plugin) ||
		!strings.Contains(err.Error(), "kept the per-user state for its backups") ||
		!strings.Contains(err.Error(), "rerun the purge") {
		t.Fatalf("purge with retained backup = %v", err)
	}
	for path, want := range map[string][]byte{plugin: edited, receipt: backup} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("purge changed %s: %v", path, err)
		}
	}
	if err := os.WriteFile(receipt, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := purge(); err == nil || !strings.Contains(err.Error(), receipt) ||
		!strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("purge with unreadable backup = %v", err)
	}
	if _, err := os.Stat(dataDir); err != nil {
		t.Fatalf("purge removed state with unreadable backup: %v", err)
	}
	// Removing the unneeded receipt is one remedy. A clean rerun then
	// removes the state but leaves the account's edited plugin alone.
	if err := os.Remove(receipt); err != nil {
		t.Fatal(err)
	}
	if err := purge(); err != nil {
		t.Fatalf("purge after removing the backup: %v", err)
	}
	if _, err := os.Lstat(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state remains after clean purge: %v", err)
	}
	if got, err := os.ReadFile(plugin); err != nil || !bytes.Equal(got, edited) {
		t.Fatalf("clean purge changed the account's plugin: %v", err)
	}
}

// Every per-user connector that keeps a backup record of an agent file it
// patches or writes (amp, antigravity, devin, hermes, kiro, opencode) keeps
// the account's state while that record is left after the teardowns, and
// the error names the file. The check reads every record in
// connector_backups, so this walks each record name the Windows cleanup
// contract allows (GAP-0262).
func TestPurgeWindowsUserStateKeepsEveryConnectorBackup(t *testing.T) {
	previous := windowsEnterpriseMutationIdentityCheck
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	t.Cleanup(func() { windowsEnterpriseMutationIdentityCheck = previous })

	covered := map[string]bool{}
	for _, name := range WindowsStandalonePerUserConnectorNames() {
		var records []string
		for _, leaf := range windowsManagedRuntimeCleanupConnectors[name].backups {
			if strings.EqualFold(filepath.Ext(leaf), ".json") {
				records = append(records, leaf)
			}
		}
		for _, leaf := range records {
			covered[name] = true
			t.Run(name+"/"+leaf, func(t *testing.T) {
				home := filepath.Join(t.TempDir(), "home")
				dataDir := filepath.Join(home, ".defenseclaw")
				logical := strings.TrimSuffix(leaf, filepath.Ext(leaf))
				target := filepath.Join(home, "agent", name, logical)
				receipt := filepath.Join(dataDir, "connector_backups", name, leaf)
				for _, path := range []string{target, receipt} {
					if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				edited := []byte("edited by the account after Setup\n")
				if err := os.WriteFile(target, edited, 0o600); err != nil {
					t.Fatal(err)
				}
				backup, err := json.Marshal(map[string]any{
					"version": 1, "connector": name, "logical_name": logical,
					"path": target, "pristine_sha256": "missing",
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(receipt, backup, 0o600); err != nil {
					t.Fatal(err)
				}
				err = PurgeWindowsUserState(home, currentWindowsTestSID(t).String(), "")
				if err == nil || !strings.Contains(err.Error(), target) ||
					!strings.Contains(err.Error(), "kept the per-user state for its backups") {
					t.Fatalf("purge with a %s backup left = %v", name, err)
				}
				for path, want := range map[string][]byte{target: edited, receipt: backup} {
					if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
						t.Fatalf("purge changed %s: %v", path, err)
					}
				}
			})
		}
	}
	for _, name := range []string{"amp", "antigravity", "devin", "hermes", "kiro", "opencode"} {
		if !covered[name] {
			t.Errorf("%s keeps a backup record but its cleanup contract lists none", name)
		}
	}
}

// A purge removes managed entries as LocalSystem while retaining account
// entries, moved-aside originals and links in the same folder.
func TestPurgeWindowsUserStateKeepsAccountEntries(t *testing.T) {
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
		filepath.Join(dataDir, "hooks", "amp-plugin.ts"):                                                   "managed plugin",
		filepath.Join(dataDir, "hooks", ".hook-amp.token"):                                                 "token",
		filepath.Join(dataDir, "foreign-hook-sessions", "p-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json"): "{}",
		filepath.Join(dataDir, "foreign-hooks-backup", "amp", "settings.json"):                             "{}",
		filepath.Join(dataDir, "agent_selection.json"):                                                     "{}",
		filepath.Join(dataDir, "logs", "hook-failures.jsonl"):                                              "log",
		filepath.Join(dataDir, "personal.txt"):                                                             "account note",
		filepath.Join(rollbackDir, "hooks", "codex-hook.sh"):                                               "managed aside",
		filepath.Join(home, ".defenseclaw.rollback-notes", "keep.txt"):                                     "keep",
		filepath.Join(outside, "keep.txt"):                                                                 "keep",
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
	// The account can deny SYSTEM on a file it owns; the test denies its
	// own account, which the purge runs as here.
	windowsRelaxTestSetDACL(t, filepath.Join(dataDir, "logs", "hook-failures.jsonl"), "D:P(D;;FA;;;"+sid.String()+")")
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

	for _, path := range []string{
		filepath.Join(dataDir, "personal.txt"),
		filepath.Join(dataDir, "foreign-hooks-backup", "amp", "settings.json"),
		filepath.Join(dataDir, "link"),
	} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("the purge removed account entry %s: %v", path, err)
		}
	}
	for _, path := range []string{
		filepath.Join(dataDir, "hooks", "amp-plugin.ts"),
		filepath.Join(dataDir, "hooks", ".hook-amp.token"),
		filepath.Join(dataDir, "foreign-hook-sessions", "p-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json"),
		filepath.Join(dataDir, "agent_selection.json"),
		filepath.Join(dataDir, "logs", "hook-failures.jsonl"),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the purge left managed entry %s: %v", path, err)
		}
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
