//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/productlayout"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// The Windows CI (windows-native.yml) runs ^TestWindowsShippedRulePacks in
// ./internal/cli on an elevated runner and requires PASS, not SKIP.

// windowsShippedRulePacksTestRoot points the shipped rule pack root at a
// folder under a fresh administrator-only folder in ProgramData, so the
// production trust check (managed.ValidateTrustedRulePackTree), which walks
// the folders above, judges it as it judges the real root.
func windowsShippedRulePacksTestRoot(t *testing.T) string {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("setting the Administrators owner needs an elevated token")
	}
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := windowsShippedRulePacksSuffix()
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(programData, "DefenseClaw-ShippedPacksTest-"+suffix)
	if err := createWindowsShippedRulePacksDir(parent); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	root := filepath.Join(parent, productlayout.WindowsRulePacksFolder)
	saved := windowsShippedRulePacksRootDir
	windowsShippedRulePacksRootDir = func() (string, error) { return root, nil }
	t.Cleanup(func() { windowsShippedRulePacksRootDir = saved })
	return root
}

// windowsShippedRulePacksStandardOwner is BUILTIN\Users: a principal that is
// neither a canonical owner (SYSTEM, Administrators, TrustedInstaller) nor
// administrator-equivalent, so the trust check refuses what it owns. The
// test account cannot be used for that: on a hosted runner it is the built-in
// Administrator (RID 500), whose ownership the trust check accepts as drift
// (rel-1-0-10:GAP-0093).
func windowsShippedRulePacksStandardOwner(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	if managed.WindowsAdminEquivalentPrincipal(sid) {
		t.Fatalf("%s is administrator-equivalent on this computer", sid)
	}
	return sid
}

// windowsShippedRulePacksAdminOwner is this token's user when it is an
// administrator principal outside the canonical set (the built-in
// Administrator, a direct member of local Administrators).
func windowsShippedRulePacksAdminOwner(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid
	if !managed.WindowsAdminEquivalentPrincipal(sid) {
		t.Skipf("the test account %s is not an administrator principal outside the canonical set", sid)
	}
	return sid
}

// setWindowsShippedRulePacksTestOwner makes owner the owner of path. Only
// SeRestorePrivilege lets an administrator give an object an owner that is
// not in its own token, so it is enabled on an impersonation token of this
// locked thread for the one call.
func setWindowsShippedRulePacksTestOwner(t *testing.T, path string, owner *windows.SID) {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.RevertToSelf() }()
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	name, err := windows.UTF16PtrFromString("SeRestorePrivilege")
	if err != nil {
		t.Fatal(err)
	}
	privileges := windows.Tokenprivileges{PrivilegeCount: 1}
	if err := windows.LookupPrivilegeValue(nil, name, &privileges.Privileges[0].Luid); err != nil {
		t.Fatal(err)
	}
	privileges.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	if err := windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
		t.Fatalf("set the owner of %s to %s: %v", path, owner, err)
	}
}

func windowsShippedRulePacksTestFiles(t *testing.T) []policyassets.File {
	t.Helper()
	files, err := policyassets.ShippedRulePackFiles()
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// TestWindowsShippedRulePacksConverges covers #1445: the lifecycle helper
// writes this release's packs once, administrator-only under the real trust
// check; a repeated run changes nothing; a changed or added file is replaced
// by a checked copy; uninstall's removal takes the root.
func TestWindowsShippedRulePacksConverges(t *testing.T) {
	root := windowsShippedRulePacksTestRoot(t)
	files := windowsShippedRulePacksTestFiles(t)
	folder, changed, _, err := installWindowsShippedRulePacks()
	if err != nil || !changed {
		t.Fatalf("first run = %q changed %v, %v", folder, changed, err)
	}
	if problem := windowsShippedRulePacksProblem(folder, files, ""); problem != "" {
		t.Fatalf("written folder under the real trust check: %s", problem)
	}
	if owned, err := windowsPathOwnedByAdministrators(folder); err != nil || !owned {
		t.Fatalf("folder owner trusted = %v, %v", owned, err)
	}
	if _, changed, _, err := installWindowsShippedRulePacks(); err != nil || changed {
		t.Fatalf("repeat run changed %v, %v; want no change", changed, err)
	}
	suppressions := filepath.Join(folder, "strict", "suppressions.yaml")
	if err := os.WriteFile(suppressions, []byte("suppressions: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "strict", "rules", "extra.yaml"), []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, _, err := installWindowsShippedRulePacks(); err != nil || !changed {
		t.Fatalf("run after an edit changed %v, %v; want a rewrite", changed, err)
	}
	for _, file := range files {
		if file.Path == "strict/suppressions.yaml" {
			got, err := os.ReadFile(suppressions)
			if err != nil || !bytes.Equal(got, file.Data) {
				t.Fatalf("suppressions.yaml was not restored: %v", err)
			}
		}
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 1 {
		t.Fatalf("root holds %d entries (%v), want only the release folder", len(entries), err)
	}
	if err := removeWindowsShippedRulePacksRoot(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("root stays after removal: %v", err)
	}
}

// TestWindowsShippedRulePacksRealTrustMovesAnUntrustedRootAside covers a root
// a standard account created first: it is moved aside, removed, never
// adopted, and the packs land in a root Administrators own.
func TestWindowsShippedRulePacksRealTrustMovesAnUntrustedRootAside(t *testing.T) {
	root := windowsShippedRulePacksTestRoot(t)
	user := windowsShippedRulePacksStandardOwner(t)
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	setWindowsShippedRulePacksTestOwner(t, root, user)
	folder, changed, notes, err := installWindowsShippedRulePacks()
	if err != nil || !changed {
		t.Fatalf("run over an untrusted root = %q changed %v, %v", folder, changed, err)
	}
	if len(notes) == 0 || !strings.Contains(notes[0], "aside") {
		t.Errorf("notes = %v, want the move named", notes)
	}
	if owned, err := windowsPathOwnedByAdministrators(root); err != nil || !owned {
		t.Fatalf("root owner trusted = %v, %v", owned, err)
	}
	if left := windowsShippedRulePacksUntrusted(root); len(left) != 0 {
		t.Fatalf("moved-aside folders stay: %v", left)
	}
	if problem := windowsShippedRulePacksProblem(folder, windowsShippedRulePacksTestFiles(t), ""); problem != "" {
		t.Fatalf("written folder: %s", problem)
	}
}

// TestWindowsShippedRulePacksRealTrustRewritesALinkInside covers a symbolic
// link planted in the release folder: the folder is not exact, it is
// replaced, and the link's target is left as it was.
func TestWindowsShippedRulePacksRealTrustRewritesALinkInside(t *testing.T) {
	windowsShippedRulePacksTestRoot(t)
	files := windowsShippedRulePacksTestFiles(t)
	folder, _, _, err := installWindowsShippedRulePacks()
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	kept := filepath.Join(target, "kept.yaml")
	if err := os.WriteFile(kept, []byte("kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(folder, "strict", "rules", "linked")); err != nil {
		t.Skipf("cannot create a directory symbolic link here: %v", err)
	}
	if problem := windowsShippedRulePacksProblem(folder, files, ""); !strings.Contains(problem, "link") {
		t.Fatalf("problem with a link inside = %q, want the link named", problem)
	}
	if _, changed, _, err := installWindowsShippedRulePacks(); err != nil || !changed {
		t.Fatalf("run over a link changed %v, %v; want a rewrite", changed, err)
	}
	if problem := windowsShippedRulePacksProblem(folder, files, ""); problem != "" {
		t.Fatalf("rewritten folder: %s", problem)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("the link's target was followed and removed: %v", err)
	}
}

// TestWindowsShippedRulePacksRealTrustRewritesAUserOwnedChild covers a folder
// inside the release folder that a standard principal owns (BUILTIN\\Users;
// it keeps WRITE_DAC over it): the real trust check refuses it and the folder is replaced.
func TestWindowsShippedRulePacksRealTrustRewritesAUserOwnedChild(t *testing.T) {
	windowsShippedRulePacksTestRoot(t)
	user := windowsShippedRulePacksStandardOwner(t)
	files := windowsShippedRulePacksTestFiles(t)
	folder, _, _, err := installWindowsShippedRulePacks()
	if err != nil {
		t.Fatal(err)
	}
	setWindowsShippedRulePacksTestOwner(t, filepath.Join(folder, "strict", "rules"), user)
	if problem := windowsShippedRulePacksProblem(folder, files, ""); !strings.Contains(problem, "administrator-only") {
		t.Fatalf("problem with a user-owned folder inside = %q, want the trust refusal", problem)
	}
	if _, changed, _, err := installWindowsShippedRulePacks(); err != nil || !changed {
		t.Fatalf("run over a user-owned folder changed %v, %v; want a rewrite", changed, err)
	}
	if problem := windowsShippedRulePacksProblem(folder, files, ""); problem != "" {
		t.Fatalf("rewritten folder: %s", problem)
	}
}

// TestWindowsShippedRulePacksRealTrustAcceptsAnAdministratorOwnedChild records
// the design (rel-1-0-10:GAP-0093): a folder inside the release folder owned
// by an administrator principal outside the canonical set (the built-in
// Administrator, a local Administrators member) is accepted as drift and
// logged (managed_trust_drift_advisory), as every managed trust check does:
// an administrator can take ownership of any file, so refusing one adds no
// protection. The pack is still this release's bytes, so nothing is rewritten.
func TestWindowsShippedRulePacksRealTrustAcceptsAnAdministratorOwnedChild(t *testing.T) {
	windowsShippedRulePacksTestRoot(t)
	admin := windowsShippedRulePacksAdminOwner(t)
	files := windowsShippedRulePacksTestFiles(t)
	folder, _, _, err := installWindowsShippedRulePacks()
	if err != nil {
		t.Fatal(err)
	}
	setWindowsShippedRulePacksTestOwner(t, filepath.Join(folder, "strict", "rules"), admin)
	if problem := windowsShippedRulePacksProblem(folder, files, ""); problem != "" {
		t.Fatalf("an administrator-owned folder inside = %q, want it accepted as drift", problem)
	}
	if _, changed, _, err := installWindowsShippedRulePacks(); err != nil || changed {
		t.Fatalf("run over an administrator-owned folder changed %v, %v; want no change", changed, err)
	}
}
