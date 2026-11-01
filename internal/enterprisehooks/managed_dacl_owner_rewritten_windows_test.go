// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// writeOwnerRewrittenTestFile creates path owned by target with the DACL
// sddl (a "D:P(...)" string; "<T>" stands for target).
func writeOwnerRewrittenTestFile(t *testing.T, path string, target *windows.SID, sddl string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`{"generation":"fixture"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	setOwnerRewrittenTestDACL(t, path, target, sddl)
}

func setOwnerRewrittenTestDACL(t *testing.T, path string, target *windows.SID, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(strings.ReplaceAll(sddl, "<T>", target.String()))
	if err != nil {
		t.Fatalf("build %s: %v", sddl, err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL of %s: %v", sddl, err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		target, nil, dacl, nil); err != nil {
		t.Fatalf("set %s on %s: %v", sddl, path, err)
	}
}

func ownerRewrittenTestSDDL(t *testing.T, path string) string {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

const (
	ownerRewrittenShapeSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;<T>)"
	// SetNamedSecurityInfo stores no inherit-only entry on a file, so this
	// fixture holds the three entries; the inherit-only OWNER RIGHTS form is
	// what an owner write alone leaves (first test) and the matcher test.
	inheritOnlyShapeSDDL   = "D:P(A;IO;RC;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;<T>)"
	canonicalFileShapeSDDL = "D:P(A;;RC;;;OW)(A;;0x1301bf;;;<T>)(A;;FA;;;SY)(A;;FA;;;BA)"
)

// Windows itself takes the OWNER RIGHTS entry out of effect when the owner
// is written, even with the same owner: a raw owner write leaves it
// inherit-only, icacls /setowner (and takeown and back, an icacls /T through
// a directory link) removes it. Both are the shapes GAP-0303 found on the
// account's generation files.
func TestWindowsOwnerWriteDropsOwnerRightsAndTheBundleCheckAcceptsTheResult(t *testing.T) {
	target := currentWindowsTestSID(t)
	dir := t.TempDir()
	cases := map[string]func(t *testing.T, path string){
		"SetSecurityInfo owner write": func(t *testing.T, path string) {
			extended, err := winpath.Extended(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
				windows.OWNER_SECURITY_INFORMATION, target, nil, nil, nil); err != nil {
				t.Fatalf("rewrite the owner: %v", err)
			}
		},
		"icacls setowner": func(t *testing.T, path string) {
			account, domain, _, err := target.LookupAccount("")
			if err != nil {
				t.Skipf("account name of the test token: %v", err)
			}
			out, err := exec.Command("icacls.exe", path, "/setowner", domain+`\`+account, "/Q").CombinedOutput()
			if err != nil {
				t.Fatalf("icacls /setowner: %v: %s", err, out)
			}
		},
	}
	index := 0
	for name, rewrite := range cases {
		index++
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, ".managed-runtime-codex-"+strings.Repeat(string(rune('a'+index)), 32)+".json")
			writeOwnerRewrittenTestFile(t, path, target, canonicalFileShapeSDDL)
			if err := validateWindowsUserPathElement(path, target, false, false, true); err != nil {
				t.Fatalf("canonical bundle refused: %v", err)
			}
			rewrite(t, path)
			// Before the fix: every collection refused this file and an
			// uninstall ended 1603 (GAP-0303).
			if err := validateWindowsUserPathElement(path, target, false, false, true); err == nil {
				t.Fatalf("strict check accepted the owner-rewritten file %s", ownerRewrittenTestSDDL(t, path))
			}
			if err := validateWindowsManagedRuntimeBundleElement(path, target); err != nil {
				t.Fatalf("bundle trust check refused the owner-rewritten file %s: %v", ownerRewrittenTestSDDL(t, path), err)
			}
			restored, err := restoreWindowsManagedFileOwnerRights(path, target)
			if err != nil || !restored {
				t.Fatalf("restore OWNER RIGHTS: restored=%v err=%v", restored, err)
			}
			if err := validateWindowsUserPathElement(path, target, false, false, true); err != nil {
				t.Fatalf("restored file is not canonical: %v (%s)", err, ownerRewrittenTestSDDL(t, path))
			}
			if again, err := restoreWindowsManagedFileOwnerRights(path, target); err != nil || again {
				t.Fatalf("second restore: restored=%v err=%v, want a no-op", again, err)
			}
		})
	}
}

func TestWindowsManagedRuntimeBundleCheckRefusesAForeignOrLooserACL(t *testing.T) {
	target := currentWindowsTestSID(t)
	dir := t.TempDir()
	cases := map[string]string{
		"Users write ACE added":    "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;<T>)(A;;0x1301bf;;;BU)",
		"Users read ACE added":     "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;<T>)(A;;0x1200a9;;;BU)",
		"Everyone replaces BA":     "D:P(A;;FA;;;SY)(A;;FA;;;WD)(A;;0x1301bf;;;<T>)",
		"account full control":     "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<T>)",
		"account WRITE_DAC":        "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1701bf;;;<T>)",
		"Administrators missing":   "D:P(A;;FA;;;SY)(A;;0x1301bf;;;<T>)",
		"deny entry added":         "D:P(D;;WD;;;<T>)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;<T>)",
		"canonical plus a foreign": "D:P(A;;RC;;;OW)(A;;0x1301bf;;;<T>)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)",
	}
	index := 0
	for name, sddl := range cases {
		index++
		path := filepath.Join(dir, ".managed-runtime-codex-"+strings.Repeat(string(rune('a'+index)), 32)+".json")
		writeOwnerRewrittenTestFile(t, path, target, sddl)
		before := ownerRewrittenTestSDDL(t, path)
		if err := validateWindowsManagedRuntimeBundleElement(path, target); err == nil {
			t.Errorf("%s: bundle trust check accepted %s", name, before)
		}
		if restored, err := restoreWindowsManagedFileOwnerRights(path, target); err != nil || restored {
			t.Errorf("%s: restore changed it: restored=%v err=%v", name, restored, err)
		}
		if after := ownerRewrittenTestSDDL(t, path); after != before {
			t.Errorf("%s: DACL changed from %s to %s", name, before, after)
		}
	}
	// A not-protected (inheriting) file in the old shape stays refused.
	path := filepath.Join(dir, ".managed-runtime-codex-"+strings.Repeat("z", 32)+".json")
	writeOwnerRewrittenTestFile(t, path, target, ownerRewrittenShapeSDDL)
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(strings.ReplaceAll(ownerRewrittenShapeSDDL, "<T>", target.String()))
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsManagedRuntimeBundleElement(path, target); err == nil {
		t.Errorf("unprotected old-shape file accepted: %s", ownerRewrittenTestSDDL(t, path))
	}
	// A hard link to an old-shape file stays refused.
	linked := filepath.Join(dir, ".managed-runtime-codex-"+strings.Repeat("y", 32)+".json")
	writeOwnerRewrittenTestFile(t, linked, target, ownerRewrittenShapeSDDL)
	if err := os.Link(linked, filepath.Join(dir, "second-name.json")); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsManagedRuntimeBundleElement(linked, target); err == nil {
		t.Error("hard-linked old-shape file accepted")
	}
	if restored, err := restoreWindowsManagedFileOwnerRights(linked, target); err != nil || restored {
		t.Errorf("hard-linked file restored: restored=%v err=%v", restored, err)
	}
}

func TestWindowsManagedRuntimeCleanupCanonicalFileAcceptsOnlyTheOwnerRewrittenShape(t *testing.T) {
	target := currentWindowsTestSID(t)
	dir := t.TempDir()
	runtimeTarget := windowsManagedRuntimeTarget{home: dir, data: dir, sid: target}
	check := func(sddl string) error {
		path := filepath.Join(dir, ".hookcfg")
		_ = os.Remove(path)
		writeOwnerRewrittenTestFile(t, path, target, sddl)
		ptr, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := windows.CreateFile(ptr, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(handle)
		_, err = validateWindowsManagedRuntimeCleanupFileHandle(handle, runtimeTarget, windowsManagedRuntimeCleanupCanonicalFile, path)
		return err
	}
	if err := check(canonicalFileShapeSDDL); err != nil {
		t.Fatalf("canonical cleanup file refused: %v", err)
	}
	for _, sddl := range []string{ownerRewrittenShapeSDDL, inheritOnlyShapeSDDL} {
		if err := check(sddl); err != nil {
			t.Fatalf("owner-rewritten cleanup file %s refused: %v", sddl, err)
		}
	}
	for _, sddl := range []string{
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;<T>)(A;;0x1301bf;;;BU)",
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<T>)",
	} {
		if err := check(sddl); err == nil {
			t.Errorf("cleanup accepted %s", sddl)
		}
	}
}

// End to end: generation bundles an owner write left without OWNER RIGHTS
// are classified (upgrade pre-check), restored by the collecting GC when
// they stay, collected when they are unselected, and an uninstall retire
// removes the selected one (GAP-0303: every step refused before).
func TestWindowsManagedRuntimeGenerationGCAfterAnOwnerWrite(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := currentWindowsTestSID(t)
	for _, path := range []string{dataDir, hookDir} {
		// An elevated test token creates folders owned by Administrators.
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION, target, nil, nil, nil); err != nil {
			t.Fatalf("own %s: %v", path, err)
		}
		if err := setWindowsUserPathProtection(path, target, true); err != nil {
			t.Fatalf("protect %s: %v", path, err)
		}
	}
	selectorPath := filepath.Join(base, windowsManagedRuntimeSelectorFile)
	originalPath := windowsManagedRuntimeSelectorPathResolver
	originalOwner := windowsManagedPolicyOwnerSID
	originalDirTrust := windowsManagedPolicyDirTrustCheck
	originalAncestorTrust := windowsManagedPolicyAncestorTrustCheck
	originalFileTrust := windowsManagedPolicyFileTrustCheck
	originalMutation := windowsManagedRuntimeSelectorMutationAuthorize
	originalVerifyAuthorize := windowsManagedRuntimeSelectorVerifyAuthorize
	originalHookTrust := windowsEnterpriseHookTrustCheck
	originalMinAge := windowsManagedRuntimeGenerationGCMinAge
	windowsManagedRuntimeSelectorPathResolver = func(string) (string, error) { return selectorPath, nil }
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return target, nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	windowsManagedRuntimeSelectorMutationAuthorize = func() error { return nil }
	windowsManagedRuntimeSelectorVerifyAuthorize = func() error { return nil }
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		windowsManagedRuntimeSelectorPathResolver = originalPath
		windowsManagedPolicyOwnerSID = originalOwner
		windowsManagedPolicyDirTrustCheck = originalDirTrust
		windowsManagedPolicyAncestorTrustCheck = originalAncestorTrust
		windowsManagedPolicyFileTrustCheck = originalFileTrust
		windowsManagedRuntimeSelectorMutationAuthorize = originalMutation
		windowsManagedRuntimeSelectorVerifyAuthorize = originalVerifyAuthorize
		windowsEnterpriseHookTrustCheck = originalHookTrust
		windowsManagedRuntimeGenerationGCMinAge = originalMinAge
	})

	now := time.Now().UTC().Format(time.RFC3339Nano)
	desired := WindowsManagedRuntimeGenerationDesired{
		Connector:                  "codex",
		TargetSID:                  target.String(),
		DataDir:                    dataDir,
		HookExecutable:             filepath.Join(base, "defenseclaw-hook.exe"),
		GatewayAddr:                "127.0.0.1:18970",
		GatewayServiceName:         "DefenseClawGateway",
		ScopedToken:                "scoped-test-token",
		HookContractID:             "codex-hooks-v1",
		HookContractLockUpdatedAt:  now,
		HookContractEntryUpdatedAt: now,
	}
	old, err := PrepareWindowsManagedRuntimeGeneration(desired)
	if err != nil {
		t.Fatalf("prepare the older generation: %v", err)
	}
	if _, err := CommitWindowsManagedRuntimeGeneration(old); err != nil {
		t.Fatalf("commit the older generation: %v", err)
	}
	nextDesired := desired
	nextDesired.GatewayAddr = "127.0.0.1:18971"
	next, err := PrepareWindowsManagedRuntimeGeneration(nextDesired)
	if err != nil {
		t.Fatalf("prepare the newer generation: %v", err)
	}
	if _, err := CommitWindowsManagedRuntimeGeneration(next); err != nil {
		t.Fatalf("commit the newer generation: %v", err)
	}
	// The unselected older bundle survives the commit (its finalize is not
	// run), as on the GAP-0303 host where it was kept while young.
	for _, path := range []string{old.BundlePath(), next.BundlePath()} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("bundle %s: %v", path, err)
		}
		setOwnerRewrittenTestDACL(t, path, target, ownerRewrittenShapeSDDL)
		if err := validateWindowsUserPathElement(path, target, false, false, true); err == nil {
			t.Fatalf("fixture %s is still canonical", path)
		}
	}
	gc := WindowsManagedRuntimeGenerationGCOptions{
		Connector:      desired.Connector,
		TargetSID:      desired.TargetSID,
		DataDir:        dataDir,
		HookExecutable: desired.HookExecutable,
	}
	// The hook reads the selected owner-rewritten bundle.
	resolve := WindowsManagedRuntimeGenerationResolveOptions{
		Connector:               nextDesired.Connector,
		TargetSID:               nextDesired.TargetSID,
		DataDir:                 nextDesired.DataDir,
		HookExecutable:          nextDesired.HookExecutable,
		MachinePolicyRegistered: true,
	}
	if current, err := ResolveWindowsManagedRuntimeGeneration(resolve); err != nil || current.GenerationID != next.GenerationID() {
		t.Fatalf("resolve the selected owner-rewritten bundle: generation=%q err=%v", current.GenerationID, err)
	}
	// The owner write reached both roots too (icacls /setowner /T). The hook
	// keeps the strict root check (a running guardian repairs the roots);
	// classification and collection accept that shape.
	for _, path := range []string{dataDir, hookDir} {
		ownerWriteForTest(t, path, target)
		if err := validateWindowsUserPathElement(path, target, true, true, true); err == nil {
			t.Fatalf("root %s is still canonical after the owner write", path)
		}
	}
	// The pre-transaction classification reads and changes nothing.
	if err := ClassifyWindowsManagedRuntimeGenerations(gc); err != nil {
		t.Fatalf("classify owner-rewritten bundles: %v", err)
	}
	if got := ownerRewrittenTestSDDL(t, next.BundlePath()); strings.Contains(got, ";;;OW)") {
		t.Fatalf("classification changed a bundle: %s", got)
	}
	windowsManagedRuntimeGenerationGCMinAge = 0
	removed, err := GarbageCollectWindowsManagedRuntimeGenerations(gc)
	if err != nil || removed != 1 {
		t.Fatalf("collect after an owner write: removed=%d err=%v, want the unselected bundle", removed, err)
	}
	if _, err := os.Lstat(old.BundlePath()); !os.IsNotExist(err) {
		t.Fatalf("unselected owner-rewritten bundle survived: %v", err)
	}
	if err := validateWindowsUserPathElement(next.BundlePath(), target, false, false, true); err != nil {
		t.Fatalf("the selected bundle was not restored to the canonical DACL: %v (%s)", err, ownerRewrittenTestSDDL(t, next.BundlePath()))
	}
	for _, path := range []string{dataDir, hookDir} {
		if err := validateWindowsUserPathElement(path, target, true, true, true); err != nil {
			t.Fatalf("the collecting GC did not restore root %s: %v (%s)", path, err, ownerRewrittenTestSDDL(t, path))
		}
	}
	// Uninstall: an owner write again, then the retired finalize collects
	// the selected bundle too.
	setOwnerRewrittenTestDACL(t, next.BundlePath(), target, inheritOnlyShapeSDDL)
	removal, err := RemoveWindowsManagedRuntimeGenerationEnrollment(WindowsManagedRuntimeGenerationRemovalOptions{
		Connector:                nextDesired.Connector,
		TargetSID:                nextDesired.TargetSID,
		DataDir:                  nextDesired.DataDir,
		HookExecutable:           nextDesired.HookExecutable,
		PrimaryEnrollmentRemoved: true,
	})
	if err != nil || !removal.Changed() {
		t.Fatalf("remove the enrollment: changed=%v err=%v", removal.Changed(), err)
	}
	if err := removal.Finalize(); err != nil {
		t.Fatalf("finalize the owner-rewritten selected bundle: %v", err)
	}
	if _, err := os.Lstat(next.BundlePath()); !os.IsNotExist(err) {
		t.Fatalf("selected owner-rewritten bundle survived the uninstall finalize: %v", err)
	}
}

func ownerWriteForTest(t *testing.T, path string, target *windows.SID) {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, target, nil, nil, nil); err != nil {
		t.Fatalf("rewrite the owner of %s: %v", path, err)
	}
}

// newOwnerRewrittenTestDataDir makes <base>\.defenseclaw\hooks owned by
// target with the canonical managed folder DACLs.
func newOwnerRewrittenTestDataDir(t *testing.T, target *windows.SID) (string, string) {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dataDir, hookDir} {
		ownerWriteForTest(t, path, target)
		if err := setWindowsUserPathProtection(path, target, true); err != nil {
			t.Fatalf("protect %s: %v", path, err)
		}
		if err := validateWindowsUserPathElement(path, target, true, true, true); err != nil {
			t.Fatalf("validate %s: %v", path, err)
		}
	}
	return dataDir, hookDir
}

// The hooks folder after an owner write keeps a read-only grant of another
// product (Codex sandbox group) through the restore.
func TestWindowsOwnerRewrittenManagedFolderIsAcceptedAndRestored(t *testing.T) {
	target := currentWindowsTestSID(t)
	_, hookDir := newOwnerRewrittenTestDataDir(t, target)
	extended, err := winpath.Extended(hookDir)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	withCodex := strings.Replace(sd.String(), "D:PAI", "D:PAI(A;OICI;0x1200a9;;;"+readOnlyTestCodex+")", 1)
	withCodex = strings.Replace(withCodex, "D:P(", "D:P(A;OICI;0x1200a9;;;"+readOnlyTestCodex+")(", 1)
	codexSD, err := windows.SecurityDescriptorFromString(withCodex)
	if err != nil {
		t.Fatalf("build %s: %v", withCodex, err)
	}
	codexDACL, _, _ := codexSD.DACL()
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, codexDACL, nil); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsUserPathElement(hookDir, target, true, true, true); err != nil {
		t.Fatalf("hooks folder with the Codex read grant refused before the owner write: %v (%s)", err, ownerRewrittenTestSDDL(t, hookDir))
	}
	ownerWriteForTest(t, hookDir, target)
	if err := validateWindowsUserPathElement(hookDir, target, true, true, true); err == nil {
		t.Fatalf("strict check accepted the owner-rewritten folder %s", ownerRewrittenTestSDDL(t, hookDir))
	}
	if err := validateWindowsUserPathElementOrOwnerRewritten(hookDir, target, true); err != nil {
		t.Fatalf("owner-rewritten folder refused: %v (%s)", err, ownerRewrittenTestSDDL(t, hookDir))
	}
	restored, err := restoreWindowsUserPathOwnerRights(hookDir, target, true)
	if err != nil || !restored {
		t.Fatalf("restore the folder: restored=%v err=%v", restored, err)
	}
	if err := validateWindowsUserPathElement(hookDir, target, true, true, true); err != nil {
		t.Fatalf("restored folder is not canonical: %v (%s)", err, ownerRewrittenTestSDDL(t, hookDir))
	}
	if got := ownerRewrittenTestSDDL(t, hookDir); !strings.Contains(got, readOnlyTestCodex) {
		t.Fatalf("the restore dropped the Codex read grant: %s", got)
	}
	// A foreign write grant on the folder stays refused and untouched.
	ownerWriteForTest(t, hookDir, target)
	sd, err = windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	foreign := strings.Replace(sd.String(), "D:PAI", "D:PAI(A;OICI;0x1301bf;;;"+readOnlyTestCodex+")", 1)
	foreignSD, err := windows.SecurityDescriptorFromString(foreign)
	if err != nil {
		t.Fatal(err)
	}
	foreignDACL, _, _ := foreignSD.DACL()
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, foreignDACL, nil); err != nil {
		t.Fatal(err)
	}
	before := ownerRewrittenTestSDDL(t, hookDir)
	if err := validateWindowsUserPathElementOrOwnerRewritten(hookDir, target, true); err == nil {
		t.Fatalf("folder with a foreign write grant accepted: %s", before)
	}
	if restored, err := restoreWindowsUserPathOwnerRights(hookDir, target, true); err != nil || restored {
		t.Fatalf("folder with a foreign write grant restored: restored=%v err=%v", restored, err)
	}
	if after := ownerRewrittenTestSDDL(t, hookDir); after != before {
		t.Fatalf("folder with a foreign write grant changed from %s to %s", before, after)
	}
}

// What Setup runs with its own gateway before an older helper collects or
// purges the state of an account (teardown-managed-hooks restore-owner-rights).
func TestRestoreWindowsManagedUserStateOwnerRightsAfterAnOwnerWriteOfTheTree(t *testing.T) {
	target := currentWindowsTestSID(t)
	dataDir, hookDir := newOwnerRewrittenTestDataDir(t, target)
	bundle := filepath.Join(hookDir, ".managed-runtime-codex-"+strings.Repeat("a", 32)+".json")
	hookcfg := filepath.Join(hookDir, ".hookcfg")
	rootFile := filepath.Join(dataDir, "hook_contract_lock.json")
	foreign := filepath.Join(hookDir, "foreign.json")
	for _, path := range []string{bundle, hookcfg, rootFile} {
		writeOwnerRewrittenTestFile(t, path, target, canonicalFileShapeSDDL)
	}
	writeOwnerRewrittenTestFile(t, foreign, target, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;<T>)(A;;0x1301bf;;;BU)")
	account, domain, _, err := target.LookupAccount("")
	if err != nil {
		t.Skipf("account name of the test token: %v", err)
	}
	if out, err := exec.Command("icacls.exe", dataDir, "/setowner", domain+`\`+account, "/T", "/C", "/Q").CombinedOutput(); err != nil {
		t.Fatalf("icacls /setowner /T: %v: %s", err, out)
	}
	for _, path := range []string{dataDir, hookDir} {
		if err := validateWindowsUserPathElement(path, target, true, true, true); err == nil {
			t.Fatalf("folder %s is still canonical after icacls /setowner /T", path)
		}
	}
	foreignBefore := ownerRewrittenTestSDDL(t, foreign)
	restored, err := RestoreWindowsManagedUserStateOwnerRights(target.String(), dataDir)
	if err != nil || restored != 5 {
		t.Fatalf("restore the tree: restored=%d err=%v, want the 2 folders and 3 managed files", restored, err)
	}
	for _, path := range []string{dataDir, hookDir} {
		if err := validateWindowsUserPathElement(path, target, true, true, true); err != nil {
			t.Fatalf("folder %s not restored: %v", path, err)
		}
	}
	for _, path := range []string{bundle, hookcfg, rootFile} {
		if err := validateWindowsUserPathElement(path, target, false, false, true); err != nil {
			t.Fatalf("file %s not restored: %v", path, err)
		}
	}
	if after := ownerRewrittenTestSDDL(t, foreign); after != foreignBefore {
		t.Fatalf("file with a foreign write grant changed from %s to %s", foreignBefore, after)
	}
	if again, err := RestoreWindowsManagedUserStateOwnerRights(target.String(), dataDir); err != nil || again != 0 {
		t.Fatalf("second restore: restored=%d err=%v, want a no-op", again, err)
	}
	// Another account is not this one.
	if _, err := RestoreWindowsManagedUserStateOwnerRights("S-1-5-18", dataDir); err == nil {
		t.Fatal("restore accepted LocalSystem as the account")
	}
}

// The owner-rewritten shape counts only for an object the account owns: owned
// by Administrators or by another account it is refused by the bundle trust
// check and left alone by the restore.
func TestWindowsOwnerRewrittenShapeRefusesAnotherOwner(t *testing.T) {
	target := currentWindowsTestSID(t)
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	other, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, fixture := range []struct {
		name  string
		owner *windows.SID
	}{{"administrators", administrators}, {"another account", other}} {
		name, owner := fixture.name, fixture.owner
		path := filepath.Join(dir, ".managed-runtime-codex-"+strings.Repeat(string(name[0]), 32)+".json")
		writeOwnerRewrittenTestFile(t, path, target, ownerRewrittenShapeSDDL)
		extended, err := winpath.Extended(path)
		if err != nil {
			t.Fatal(err)
		}
		// Another account as the owner needs SeRestorePrivilege, which an
		// elevated token (a GitHub runner) holds disabled.
		assignNativeOTLPFixtureOwnerOrSkip(t, extended, owner)
		if windowsUserPathOwnerRewritten(path, target, false) {
			t.Errorf("%s: owner-rewritten shape matched an object the account does not own", name)
		}
		if name == "another account" {
			if err := validateWindowsManagedRuntimeBundleElement(path, target); err == nil {
				t.Errorf("%s: bundle trust check accepted it", name)
			}
		}
		before := ownerRewrittenTestSDDL(t, path)
		if restored, err := restoreWindowsUserPathOwnerRights(path, target, false); err != nil || restored {
			t.Errorf("%s: restore changed it: restored=%v err=%v", name, restored, err)
		}
		if after := ownerRewrittenTestSDDL(t, path); after != before {
			t.Errorf("%s: DACL changed from %s to %s", name, before, after)
		}
	}
}
