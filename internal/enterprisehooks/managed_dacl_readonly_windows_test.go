// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// readOnlyWindowsTestDescriptor is the field report's .defenseclaw descriptor
// with the target account and the CodexSandboxUsers group given fixed SIDs.
func readOnlyWindowsTestDescriptor(t *testing.T, extra string) (*windows.SECURITY_DESCRIPTOR, *windows.ACL, *windows.SID) {
	t.Helper()
	target, err := windows.StringToSid(readOnlyTestTarget)
	if err != nil {
		t.Fatal(err)
	}
	sddl := "O:" + readOnlyTestTarget + "G:BAD:PAI" + extra +
		"(A;;RC;;;OW)(A;OICIIO;GA;;;SY)(A;;FA;;;SY)(A;OICIIO;GA;;;BA)(A;;FA;;;BA)" +
		"(A;;0x1301ff;;;" + readOnlyTestTarget + ")(A;OICIIO;DTSDGXGWGR;;;" + readOnlyTestTarget + ")"
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("build descriptor %s: %v", sddl, err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("descriptor DACL: %v", err)
	}
	return descriptor, dacl, target
}

func TestValidateWindowsUserPathProtectionACLToleratesCodexSandboxRead(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	codexACE := "(A;OICI;0x1200a9;;;" + readOnlyTestCodex + ")"
	dataDir := `C:\Users\dclawadmin\.defenseclaw`
	hooksDir := dataDir + `\hooks`

	descriptor, dacl, target := readOnlyWindowsTestDescriptor(t, "")
	if err := validateWindowsUserPathProtectionACL(dataDir, descriptor, dacl, target, true); err != nil {
		t.Fatalf("canonical DACL refused: %v", err)
	}

	descriptor, dacl, target = readOnlyWindowsTestDescriptor(t, codexACE)
	for _, path := range []string{dataDir, hooksDir} {
		if err := validateWindowsUserPathProtectionACL(path, descriptor, dacl, target, true); err != nil {
			t.Fatalf("%s: Codex sandbox read grant refused: %v", path, err)
		}
	}
	extras, err := inspectWindowsUserPathProtectionACL(dataDir, descriptor, dacl, target, true, true)
	if err != nil || len(extras) != 1 || extras[0].String() != readOnlyTestCodex {
		t.Fatalf("read-only extras = %v, %v; want the Codex group", extras, err)
	}
	// Every other managed folder keeps the exact DACL.
	if err := validateWindowsUserPathProtectionACL(dataDir+`\connector_backups`, descriptor, dacl, target, true); err == nil ||
		!strings.Contains(err.Error(), "has 8 ACEs, expected 7") {
		t.Fatalf("connector_backups with an extra grant: %v, want the exact-count refusal", err)
	}

	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	if err := validateWindowsUserPathProtectionACL(dataDir, descriptor, dacl, target, true); err == nil ||
		!strings.Contains(err.Error(), "has 8 ACEs, expected 7") {
		t.Fatalf("strict mode: %v, want the exact-count refusal", err)
	}
}

func TestValidateWindowsUserPathProtectionACLRefusesWriteCapableExtras(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	dataDir := `C:\Users\dclawadmin\.defenseclaw`
	for name, extra := range map[string]string{
		"modify":            "(A;OICI;0x1301bf;;;" + readOnlyTestCodex + ")",
		"write data":        "(A;OICI;0x1200ab;;;" + readOnlyTestCodex + ")",
		"delete child":      "(A;OICI;0x1200e9;;;" + readOnlyTestCodex + ")",
		"write DAC":         "(A;OICI;0x1600a9;;;" + readOnlyTestCodex + ")",
		"generic write":     "(A;OICIIO;GW;;;" + readOnlyTestCodex + ")",
		"everyone full":     "(A;OICI;FA;;;WD)",
		"deny":              "(D;OICI;0x1200a9;;;" + readOnlyTestCodex + ")",
		"admin read":        "(A;OICI;0x1200a9;;;BA)",
		"duplicate target":  "(A;OICI;0x1200a9;;;" + readOnlyTestTarget + ")",
		"creator owner":     "(A;OICIIO;GR;;;CO)",
		"system read again": "(A;;0x1200a9;;;SY)",
	} {
		descriptor, dacl, target := readOnlyWindowsTestDescriptor(t, extra)
		if err := validateWindowsUserPathProtectionACL(dataDir, descriptor, dacl, target, true); err == nil {
			t.Errorf("%s: extra ACE %s was accepted", name, extra)
		}
	}
	// A file never tolerates an extra grant.
	target, err := windows.StringToSid(readOnlyTestTarget)
	if err != nil {
		t.Fatal(err)
	}
	file, err := windows.SecurityDescriptorFromString("O:" + readOnlyTestTarget + "G:BAD:PAI(A;;0x1200a9;;;" + readOnlyTestCodex +
		")(A;;RC;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;" + readOnlyTestTarget + ")")
	if err != nil {
		t.Fatal(err)
	}
	fileDACL, _, err := file.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsUserPathProtectionACL(dataDir, file, fileDACL, target, false); err == nil {
		t.Fatal("a file DACL with an extra read grant was accepted")
	}
}

// grantWindowsReadOnlyTestACE adds an explicit allow ACE for sid to path's
// protected DACL, as Codex's sandbox setup does.
func grantWindowsReadOnlyTestACE(t *testing.T, path string, sid *windows.SID, mask windows.ACCESS_MASK) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, current)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, merged, nil); err != nil {
		t.Fatal(err)
	}
}

func windowsReadOnlyTestACECount(t *testing.T, path string) uint16 {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("read DACL of %s: %v", path, err)
	}
	return dacl.AceCount
}

// The field report: a Secure Client reinstall refused a .defenseclaw that
// Codex's sandbox had granted CodexSandboxUsers read on ("has 8 ACEs,
// expected 7"). An install plan takes it over and restores the exact DACL;
// strict mode and a per-user install folder keep the refusal; a validation
// plan accepts it unchanged. A write-capable grant is drift a Secure Client
// plan re-stamps like any retained root (26.8.4); strict mode and a
// standalone plan refuse it.
func TestWindowsManagedRuntimeInstallPlanRestampsAReadOnlyGrant(t *testing.T) {
	previous := windowsEnterpriseStandaloneProcess
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previous })
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	codex, err := windows.StringToSid(readOnlyTestCodex)
	if err != nil {
		t.Fatal(err)
	}
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	dataDir := filepath.Join(home, ".defenseclaw")
	if _, err := ensureWindowsTargetOwnedDirectoryTree(home, filepath.Join(dataDir, "hooks"), target); err != nil {
		t.Fatal(err)
	}
	canonicalCount := windowsReadOnlyTestACECount(t, dataDir)
	grantWindowsReadOnlyTestACE(t, dataDir, codex, windows.ACCESS_MASK(readOnlyTestCodexMask))
	if got := windowsReadOnlyTestACECount(t, dataDir); got != canonicalCount+1 {
		t.Fatalf("test DACL has %d ACEs, want %d", got, canonicalCount+1)
	}
	manifest := windowsManagedRuntimeTestManifest(home, target)
	manifestPath, digest := `C:\ProgramData\DefenseClaw\etc\targets.yaml`, strings.Repeat("7", 64)

	// The read-only upgrade/repair plan accepts the folder and leaves it.
	if _, err := PlanWindowsManagedRuntimeRootsForValidation(manifest, manifestPath, digest); err != nil {
		t.Fatalf("validation plan refused a read-only grant: %v", err)
	}
	if got := windowsReadOnlyTestACECount(t, dataDir); got != canonicalCount+1 {
		t.Fatalf("validation plan changed the DACL (%d ACEs)", got)
	}

	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	if _, err := PlanWindowsManagedRuntimeRoots(manifest, manifestPath, digest); err == nil ||
		!strings.Contains(err.Error(), "reject noncanonical managed runtime baseline") {
		t.Fatalf("strict install plan = %v, want the refusal", err)
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "")

	perUser := filepath.Join(dataDir, "config.yaml")
	if err := os.WriteFile(perUser, []byte("gateway: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Secure Client skips only this user and leaves the folder as it is;
	// a strict or standalone plan refuses it.
	skippedPlan, err := PlanWindowsManagedRuntimeRoots(manifest, manifestPath, digest)
	if err != nil || len(skippedPlan.Roots) != 0 || len(skippedPlan.SkippedProfiles) != 1 ||
		!strings.Contains(skippedPlan.SkippedProfiles[0].Reason, dataDir+" holds config.yaml") {
		t.Fatalf("Secure Client install plan over a per-user install folder = %+v, %v; want that user skipped", skippedPlan, err)
	}
	if got := windowsReadOnlyTestACECount(t, dataDir); got != canonicalCount+1 {
		t.Fatalf("skipping the per-user install folder changed its DACL (%d ACEs)", got)
	}
	// Strict and standalone refuse the whole plan, never skip the user. The
	// folder also carries this test's read-only grant, which they refuse
	// first, so the refusal is asserted rather than its reason.
	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	if refused, err := PlanWindowsManagedRuntimeRoots(manifest, manifestPath, digest); err == nil ||
		len(refused.SkippedProfiles) != 0 ||
		!strings.Contains(err.Error(), "reject noncanonical managed runtime baseline") {
		t.Fatalf("strict install plan over a per-user install folder = %+v, %v; want the refusal", refused, err)
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	if refused, err := PlanWindowsManagedRuntimeRoots(manifest, manifestPath, digest); err == nil ||
		len(refused.SkippedProfiles) != 0 ||
		!strings.Contains(err.Error(), "reject noncanonical managed runtime baseline") {
		t.Fatalf("standalone install plan over a per-user install folder = %+v, %v; want the refusal", refused, err)
	}
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	if err := os.Remove(perUser); err != nil {
		t.Fatal(err)
	}

	plan, err := PlanWindowsManagedRuntimeRoots(manifest, manifestPath, digest)
	if err != nil {
		t.Fatalf("install plan refused a read-only grant: %v", err)
	}
	if len(plan.Roots) != 1 || plan.Roots[0].Baseline != windowsManagedRuntimeBaselineCanonical {
		t.Fatalf("plan roots = %+v, want canonical baseline", plan.Roots)
	}
	if got := windowsReadOnlyTestACECount(t, dataDir); got != canonicalCount {
		t.Fatalf("install plan left %d ACEs, want the canonical %d", got, canonicalCount)
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, dataDir, target)

	grantWindowsReadOnlyTestACE(t, dataDir, codex, windows.ACCESS_MASK(0x001301bf))
	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	if _, err := PlanWindowsManagedRuntimeRoots(manifest, manifestPath, digest); err == nil ||
		!strings.Contains(err.Error(), "reject noncanonical managed runtime baseline") {
		t.Fatalf("strict install plan over a write grant = %v, want the refusal", err)
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	if _, err := PlanWindowsManagedRuntimeRoots(manifest, manifestPath, digest); err == nil ||
		!strings.Contains(err.Error(), "reject noncanonical managed runtime baseline") {
		t.Fatalf("standalone install plan over a write grant = %v, want the refusal", err)
	}
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	plan, err = PlanWindowsManagedRuntimeRoots(manifest, manifestPath, digest)
	if err != nil || len(plan.Roots) != 1 || len(plan.RepairedProfiles) != 1 || len(plan.SkippedProfiles) != 0 {
		t.Fatalf("Secure Client install plan over a write grant = %+v, %v; want the root repaired", plan, err)
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, dataDir, target)
}

// GAP-1334: a guardian stopped in the middle of a Hermes setup (or a
// rolled-back lifecycle that stopped it) leaves the user's .defenseclaw in
// the setup shape. The Upgrade/Repair plan refused it as a noncanonical
// baseline before the generation GC that recovers it ran, so the SYSTEM
// /repair failed 1603. The plan now recovers that stale shape; a relax a
// running setup holds and any other DACL stay refused and unchanged.
func TestWindowsManagedRuntimeRepairPlanRecoversAStaleGuardianSetupRelax(t *testing.T) {
	previousStandalone := windowsEnterpriseStandaloneProcess
	previousWait, previousStale := windowsManagedRuntimeSetupRelaxWait, windowsSetupRelaxIsStale
	t.Cleanup(func() {
		windowsEnterpriseStandaloneProcess = previousStandalone
		windowsManagedRuntimeSetupRelaxWait, windowsSetupRelaxIsStale = previousWait, previousStale
	})
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	windowsManagedRuntimeSetupRelaxWait = 50 * time.Millisecond
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	dataDir := filepath.Join(home, ".defenseclaw")
	if _, err := ensureWindowsTargetOwnedDirectoryTree(home, filepath.Join(dataDir, "hooks"), target); err != nil {
		t.Fatal(err)
	}
	setDACL := func(sddl string) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(dataDir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	manifest := windowsManagedRuntimeTestManifest(home, target)
	manifestPath, digest := `C:\ProgramData\DefenseClaw\etc\targets.yaml`, strings.Repeat("7", 64)
	plan := func() error {
		_, err := PlanWindowsManagedRuntimeRootsForValidation(manifest, manifestPath, digest)
		return err
	}

	setDACL(windowsSetupRelaxedDirectorySDDL)
	windowsSetupRelaxIsStale = func(string, *windows.SID) bool { return false }
	if err := plan(); err == nil || !strings.Contains(err.Error(), "reject noncanonical managed runtime baseline") {
		t.Fatalf("plan over a running setup's relax = %v, want the refusal", err)
	}
	if !windowsManagedRuntimeDirSetupRelaxed(dataDir, target) {
		t.Fatal("a running setup's relax was changed")
	}

	windowsSetupRelaxIsStale = func(string, *windows.SID) bool { return true }
	if err := plan(); err != nil {
		t.Fatalf("repair plan over a stale guardian setup relax: %v", err)
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, dataDir, target)

	setDACL("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err := plan(); err == nil || !strings.Contains(err.Error(), "reject noncanonical managed runtime baseline") {
		t.Fatalf("plan over a foreign DACL = %v, want the refusal", err)
	}
}
