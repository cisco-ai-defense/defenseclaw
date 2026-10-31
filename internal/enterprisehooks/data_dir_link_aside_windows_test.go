//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// plantWindowsAccountJunction makes link a junction to target, owned by the
// account as a standard user's own junction would be.
func plantWindowsAccountJunction(t *testing.T, link, target string, owner *windows.SID) {
	t.Helper()
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Fatalf("mklink /J %s: %v: %s", link, err, output)
	}
	current, err := windowsPathOwnerNoFollow(link)
	if err != nil {
		t.Fatal(err)
	}
	if current != nil && current.Equals(owner) {
		return
	}
	extended, err := winpath.Extended(link)
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		t.Fatal(err)
	}
	// The link itself, never what it names.
	handle, err := windows.CreateFile(ptr, windows.WRITE_OWNER|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if err := RunWithWindowsAdministratorOwnerRestorePrivilege(func() error {
		return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
	}); err != nil {
		t.Fatalf("set junction owner: %v", err)
	}
}

// outsideDataDirTree is a folder outside the profile that holds an acp
// folder and a canary file, the shape of the GAP-0193 cell.
func outsideDataDirTree(t *testing.T, home string) (string, string) {
	t.Helper()
	outside := filepath.Join(filepath.Dir(home), "outside-data-dir")
	if err := os.MkdirAll(filepath.Join(outside, "acp"), 0o700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(outside, "acp", "canary.txt")
	if err := os.WriteFile(canary, []byte("outside canary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return outside, canary
}

func requireOutsideDataDirTreeUnchanged(t *testing.T, outside, canary string) {
	t.Helper()
	if got, err := os.ReadFile(canary); err != nil || string(got) != "outside canary\n" {
		t.Fatalf("the folder the junction named changed: %q err=%v", got, err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "acp" {
		t.Fatalf("enrollment wrote into the folder the junction named: %v", entries)
	}
	acp, err := os.ReadDir(filepath.Join(outside, "acp"))
	if err != nil || len(acp) != 1 {
		t.Fatalf("enrollment changed the acp folder the junction named: %v err=%v", acp, err)
	}
}

func requirePlainProtectedDataDir(t *testing.T, dataDir string) {
	t.Helper()
	info, err := os.Lstat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := winpath.UTF16Ptr(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.Fatalf("%s is not a plain folder after the enrollment (mode %v, attributes 0x%x)", dataDir, info.Mode(), attributes)
	}
}

// A standard user whose .defenseclaw is a junction it made itself refused its
// own enrollment, and that failed reconcile refused every administrator
// ensure and uninstall on the computer (GAP-0193). The enrollment now moves
// the account's own link aside without following it and protects a new
// folder.
func TestWindowsClaudeEnrollmentMovesAccountOwnDataDirJunctionAside(t *testing.T) {
	stubWindowsAuthorizedRepairIdentityChecks(t)
	var outside, canary string
	fixture := newWindowsManagedInstallFixtureWithHomeSetup(t, nil, func(home string, targetSID *windows.SID) {
		if err := setWindowsUserPathProtection(home, targetSID, true); err != nil {
			t.Fatalf("harden test home: %v", err)
		}
		outside, canary = outsideDataDirTree(t, home)
		plantWindowsAccountJunction(t, filepath.Join(home, ".defenseclaw"), outside, targetSID)
	})
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatalf("Install with the account's own .defenseclaw junction: %v", err)
	}
	dataDir := filepath.Join(fixture.home, ".defenseclaw")
	requirePlainProtectedDataDir(t, dataDir)
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
	if _, err := os.Lstat(windowsManagedObstructionQuarantinePath(dataDir)); err == nil {
		t.Fatal("the moved junction stayed in its quarantine slot after the enrollment")
	}
}

// Only the canonical DefenseClaw folder and its hooks folder are moved aside;
// a link anywhere else in the profile is left for the checks that refuse it.
func TestWindowsDataDirLinkAsideLeavesOtherLinks(t *testing.T) {
	stubWindowsAuthorizedRepairIdentityChecks(t)
	targetSID := currentWindowsTestSID(t)
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	setWindowsTestPathExactOwner(t, home, targetSID)
	outside, canary := outsideDataDirTree(t, home)
	other := filepath.Join(home, ".codex")
	plantWindowsAccountJunction(t, other, outside, targetSID)
	if err := moveWindowsTargetOwnedDataDirLinksAside(home, other, targetSID); err != nil {
		t.Fatal(err)
	}
	if err := prepareWindowsGenericPath(home, other, targetSID, true, false, false, "footprint directory"); err == nil ||
		!strings.Contains(err.Error(), "refusing reparse point") {
		t.Fatalf("a link outside the DefenseClaw folder was not refused: %v", err)
	}
	if _, err := os.Lstat(windowsManagedObstructionQuarantinePath(other)); err == nil {
		t.Fatal("a link outside the DefenseClaw folder was moved aside")
	}

	// The account's own junction at the DefenseClaw folder is moved aside,
	// so the first-enrollment check finds no folder and the enrollment
	// creates one.
	dataDir := filepath.Join(home, ".defenseclaw")
	plantWindowsAccountJunction(t, dataDir, outside, targetSID)
	if err := prepareWindowsGenericPath(home, dataDir, targetSID, true, false, false, "data dir"); err == nil {
		t.Fatal("the first-enrollment check accepted a junction at the DefenseClaw folder")
	}
	if err := moveWindowsTargetOwnedDataDirLinksAside(home, dataDir, targetSID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the junction is still at the DefenseClaw folder: %v", err)
	}
	if err := prepareWindowsGenericPath(home, dataDir, targetSID, true, false, false, "data dir"); err != nil {
		t.Fatalf("first-enrollment check after the junction was moved aside: %v", err)
	}
	cleanupWindowsManagedObstructionQuarantine(dataDir, targetSID)
	if _, err := os.Lstat(windowsManagedObstructionQuarantinePath(dataDir)); err == nil {
		t.Fatal("the DefenseClaw folder quarantine slot survived its cleanup")
	}

	// So is a junction at the hooks folder of a plain DefenseClaw folder.
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	setWindowsTestPathExactOwner(t, dataDir, targetSID)
	hooks := filepath.Join(dataDir, "hooks")
	plantWindowsAccountJunction(t, hooks, outside, targetSID)
	if err := moveWindowsTargetOwnedDataDirLinksAside(home, dataDir, targetSID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(hooks); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the junction is still at the hooks folder: %v", err)
	}
	requirePlainProtectedDataDir(t, dataDir)
	cleanupWindowsManagedObstructionQuarantine(hooks, targetSID)
	if _, err := os.Lstat(windowsManagedObstructionQuarantinePath(hooks)); err == nil {
		t.Fatal("the hooks quarantine slot survived its cleanup")
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
}
