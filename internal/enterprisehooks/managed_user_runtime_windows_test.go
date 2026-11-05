// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// gap45ManagedFileSDDL and gap45ManagedDirSDDL are the DACLs the field
// leftovers carried (cowork-1-0-8 GAP-0045, icacls on vm-dc-cowork-win11):
// LocalSystem and Administrators full control, the account Modify, and the
// guardian's read-only OWNER RIGHTS entry.
func gap45ManagedSDDL(sid *windows.SID, directory bool) string {
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	return "D:P(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)(A;" + inherit + ";0x1301bf;;;" + sid.String() + ")(A;;RC;;;OW)"
}

func gap45SetSecurity(t *testing.T, path string, owner *windows.SID, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := RunWithWindowsAdministratorOwnerRestorePrivilege(func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			owner, nil, acl, nil)
	}); err != nil {
		t.Fatalf("set security of %s: %v", path, err)
	}
}

// gap45Own makes the account the owner of each path, as in the field; an
// elevated test creates them owned by Administrators.
func gap45Own(t *testing.T, owner *windows.SID, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if err := RunWithWindowsAdministratorOwnerRestorePrivilege(func() error {
			return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
		}); err != nil {
			t.Fatalf("set owner of %s: %v", path, err)
		}
	}
}

func gap45WriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// gap45FieldLeftover writes the folder a managed install and plain
// uninstall left in the field, with the managed DACL on every entry.
func gap45FieldLeftover(t *testing.T, sid *windows.SID) (string, string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	dataDir := filepath.Join(home, ".defenseclaw")
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*windows.SID{
		"hook_contract_lock.json":                     sid,
		"hook_contract_lock.json.lock":                sid,
		"agent_selection.json":                        sid,
		`hooks\claude-code-hook.sh`:                   sid,
		`hooks\.hookcfg`:                              sid,
		`hooks\.hook-claudecode.token`:                sid,
		`logs\hook-failures.jsonl`:                    sid,
		`foreign-hook-sessions\0123456789abcdef.gate`: sid,
		// Written by the account's elevated hook: owned by Administrators.
		"foreign-hook-env.json": administrators,
	}
	for rel := range files {
		gap45WriteFile(t, filepath.Join(dataDir, rel), `{"version":2,"connectors":{}}`)
	}
	for rel, owner := range files {
		gap45SetSecurity(t, filepath.Join(dataDir, rel), owner, gap45ManagedSDDL(sid, false))
	}
	for _, rel := range []string{"hooks", "logs", "foreign-hook-sessions"} {
		gap45SetSecurity(t, filepath.Join(dataDir, rel), sid, gap45ManagedSDDL(sid, true))
	}
	gap45Own(t, sid, home, dataDir)
	return home, dataDir
}

func gap45AllowMutation(t *testing.T) {
	t.Helper()
	previous := windowsEnterpriseMutationIdentityCheck
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	t.Cleanup(func() { windowsEnterpriseMutationIdentityCheck = previous })
}

// A plain standalone uninstall removes what the managed runtime wrote into
// the account's folder, managed DACL and all, and then the emptied folder,
// so a later per-user install starts from nothing (GAP-0045).
func TestRemoveWindowsManagedUserRuntimeRemovesTheFieldLeftover(t *testing.T) {
	gap45AllowMutation(t)
	sid := currentWindowsTestSID(t)
	home, dataDir := gap45FieldLeftover(t, sid)

	kept, err := RemoveWindowsManagedUserRuntime(home, sid.String(), "")
	if err != nil || kept != "" {
		t.Fatalf("cleanup = %q, %v; want the folder removed", kept, err)
	}
	if _, err := os.Lstat(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the managed leftover folder stays: %v", err)
	}
	if _, err := os.Lstat(home); err != nil {
		t.Fatalf("the profile changed: %v", err)
	}
	// A second uninstall finds nothing to do.
	if kept, err := RemoveWindowsManagedUserRuntime(home, sid.String(), ""); err != nil || kept != "" {
		t.Fatalf("second cleanup = %q, %v", kept, err)
	}
}

// Only DefenseClaw's managed entries go: the account's own files, the hooks
// the foreign-hook policy moved aside and a backup record that stays are
// kept, the emptied connector_backups folders go, and what stays returns
// to the owner-private DACL a per-user install can manage.
func TestRemoveWindowsManagedUserRuntimeKeepsWhatItDidNotWrite(t *testing.T) {
	gap45AllowMutation(t)
	sid := currentWindowsTestSID(t)
	home, dataDir := gap45FieldLeftover(t, sid)
	own := filepath.Join(dataDir, "notes.txt")
	moved := filepath.Join(dataDir, "foreign-hooks-backup", "claudecode", "20261104T072538Z", "settings.json")
	record := filepath.Join(dataDir, "connector_backups", "devin", "config.json")
	for _, path := range []string{own, moved, record} {
		gap45WriteFile(t, path, "mine")
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "connector_backups", "opencode"), 0o700); err != nil {
		t.Fatal(err)
	}
	gap45Own(t, sid,
		filepath.Join(dataDir, "foreign-hooks-backup"),
		filepath.Join(dataDir, "foreign-hooks-backup", "claudecode"),
		filepath.Dir(moved), moved,
		filepath.Join(dataDir, "connector_backups"),
		filepath.Dir(record), record,
		filepath.Join(dataDir, "connector_backups", "opencode"),
	)
	gap45SetSecurity(t, own, sid, gap45ManagedSDDL(sid, false))

	kept, err := RemoveWindowsManagedUserRuntime(home, sid.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"notes.txt", "foreign-hooks-backup", "connector_backups"} {
		if !strings.Contains(kept, name) {
			t.Fatalf("kept reason %q does not name %s", kept, name)
		}
	}
	for _, path := range []string{own, moved, record} {
		if got, err := os.ReadFile(path); err != nil || string(got) != "mine" {
			t.Fatalf("%s changed: %q %v", path, got, err)
		}
	}
	for _, rel := range append([]string{`connector_backups\opencode`}, windowsManagedUserRuntimeEntries...) {
		if _, err := os.Lstat(filepath.Join(dataDir, rel)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s stays: %v", rel, err)
		}
	}
	sd, err := windows.GetNamedSecurityInfo(own, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sd.String(), windowsGuardianHardenedOwnerRightsACE) {
		t.Fatalf("the kept file keeps the managed DACL: %s", sd)
	}
}

// A per-user install's folder is left exactly as found, and so is anything
// a link or junction names.
func TestRemoveWindowsManagedUserRuntimeLeavesPerUserInstallsAndLinks(t *testing.T) {
	gap45AllowMutation(t)
	sid := currentWindowsTestSID(t)

	home, dataDir := gap45FieldLeftover(t, sid)
	gap45WriteFile(t, filepath.Join(dataDir, "config.yaml"), "config_version: 8\n")
	kept, err := RemoveWindowsManagedUserRuntime(home, sid.String(), "")
	if err != nil || !strings.Contains(kept, "config.yaml, which a per-user DefenseClaw install leaves") {
		t.Fatalf("per-user install folder = %q, %v", kept, err)
	}
	for _, rel := range []string{"hook_contract_lock.json", `hooks\.hookcfg`, "foreign-hook-env.json"} {
		if _, err := os.Lstat(filepath.Join(dataDir, rel)); err != nil {
			t.Fatalf("a per-user install's %s was removed: %v", rel, err)
		}
	}

	home, dataDir = gap45FieldLeftover(t, sid)
	outside, canary := outsideDataDirTree(t, home)
	plantWindowsAccountJunction(t, filepath.Join(dataDir, "hooks", "linked"), outside, sid)
	kept, err = RemoveWindowsManagedUserRuntime(home, sid.String(), "")
	if err != nil || !strings.Contains(kept, `hooks\linked`) {
		t.Fatalf("junction below hooks = %q, %v", kept, err)
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
	if _, err := os.Lstat(filepath.Join(dataDir, "hook_contract_lock.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the contract lock stays beside a junction: %v", err)
	}

	linkHome := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(linkHome, 0o700); err != nil {
		t.Fatal(err)
	}
	outside, canary = outsideDataDirTree(t, linkHome)
	plantWindowsAccountJunction(t, filepath.Join(linkHome, ".defenseclaw"), outside, sid)
	if _, err := RemoveWindowsManagedUserRuntime(linkHome, sid.String(), ""); err == nil || !strings.Contains(err.Error(), "left as found") {
		t.Fatalf("junction at the folder = %v", err)
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
}

// Only LocalSystem changes another account's folder.
func TestRemoveWindowsManagedUserRuntimeRequiresLocalSystem(t *testing.T) {
	sid := currentWindowsTestSID(t)
	home, dataDir := gap45FieldLeftover(t, sid)
	previous := windowsEnterpriseMutationIdentityCheck
	windowsEnterpriseMutationIdentityCheck = func() error { return errors.New("not LocalSystem") }
	t.Cleanup(func() { windowsEnterpriseMutationIdentityCheck = previous })
	if _, err := RemoveWindowsManagedUserRuntime(home, sid.String(), ""); err == nil {
		t.Fatal("cleanup ran without LocalSystem")
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "hook_contract_lock.json")); err != nil {
		t.Fatalf("cleanup without LocalSystem changed the folder: %v", err)
	}
}
