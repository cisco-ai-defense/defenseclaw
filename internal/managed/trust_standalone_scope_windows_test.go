//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// usersWriteDACL grants BUILTIN\Users write: drift no standard user may hold.
const usersWriteDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)"

// canonicalTestDACL is the repaired form: SYSTEM and Administrators only. An
// OWNER RIGHTS entry would itself be an untrusted writer to the strict walk;
// the owner keeps its implicit WRITE_DAC.
const canonicalTestDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// driftedPolicyFileForTest writes a file with a BUILTIN\Users write grant and
// confirms the strict walk refuses only that grant, so a later acceptance can
// only come from the drift tolerance under test.
func driftedPolicyFileForTest(t *testing.T, name string) string {
	t.Helper()
	t.Setenv(TrustStrictAncestorsEnv, "")
	t.Setenv(ConfigPathEnv, "")
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("ok"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	setTestFileDACL(t, path, testDACL(t, canonicalTestDACL), true)
	if err := ValidateTrustedFilePath(path, "fixture"); err != nil {
		t.Skipf("the process user does not own a trusted temp file here: %v", err)
	}
	setTestFileDACL(t, path, testDACL(t, usersWriteDACL), true)
	if err := ValidateTrustedFilePath(path, "fixture"); err == nil {
		t.Fatal("ValidateTrustedFilePath accepted a Users writer; the strict API must be unchanged")
	}
	return path
}

func pinTrustProfileForTest(t *testing.T, standalone bool) {
	t.Helper()
	previous := windowsStandaloneTrustScope
	t.Cleanup(func() { windowsStandaloneTrustScope = previous })
	if standalone {
		t.Setenv(EnterpriseProfileEnv, ProfileStandalone)
		return
	}
	t.Setenv(EnterpriseProfileEnv, "")
	// The test binary never runs from a standalone install root; pin that
	// half too so a runner layout cannot decide the profile.
	windowsStandaloneTrustScope = func() bool { return StandaloneTrustScope() }
}

func stubConfigRepairForTest(t *testing.T, repair func(path string) CanonicalOutcome) *int {
	t.Helper()
	calls := 0
	previous := windowsConfigEnsureCanonical
	t.Cleanup(func() { windowsConfigEnsureCanonical = previous })
	windowsConfigEnsureCanonical = func(path string, kind ObjectKind, _ CanonicalOptions) (CanonicalResult, error) {
		calls++
		return CanonicalResult{Path: path, Kind: kind, Outcome: repair(path)}, nil
	}
	return &calls
}

// GAP-0561: on the standalone profile a drifted config.yaml or guardian
// manifest is refused with the strict verdict, as before 26.8.4.
func TestStandaloneTrustRefusesDriftedConfigAndManifest(t *testing.T) {
	for _, tc := range []struct{ name, file, label string }{
		{"config", "config.yaml", "managed config"},
		{"manifest", "targets.yaml", "hook guardian manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := driftedPolicyFileForTest(t, tc.file)
			pinTrustProfileForTest(t, true)
			_ = captureTrustDrift(t)
			strict := ValidateTrustedFilePath(path, tc.label)
			var err error
			if tc.name == "config" {
				err = ValidateTrustedConfigPath(path)
			} else {
				err = ValidateTrustedPolicyFilePath(path, tc.label)
			}
			if err == nil {
				t.Fatalf("standalone accepted a %s with a Users writer", tc.file)
			}
			if err.Error() != strict.Error() {
				t.Fatalf("standalone error = %q, want the strict verdict %q", err, strict)
			}
		})
	}
}

// trustedThenDriftedConfigForTest pins the standalone profile and the
// service config path, reads config.yaml once while it is trusted (which
// records its content), then grants BUILTIN\Users write.
func trustedThenDriftedConfigForTest(t *testing.T) string {
	t.Helper()
	path := driftedPolicyFileForTest(t, "config.yaml")
	setTestFileDACL(t, path, testDACL(t, canonicalTestDACL), true)
	pinTrustProfileForTest(t, true)
	t.Setenv(ConfigPathEnv, path)
	if err := ValidateTrustedConfigPath(path); err != nil {
		t.Fatalf("trusted config.yaml refused: %v", err)
	}
	setTestFileDACL(t, path, testDACL(t, usersWriteDACL), true)
	return path
}

func restampRepairForTest(t *testing.T) func(string) CanonicalOutcome {
	return func(repaired string) CanonicalOutcome {
		setTestFileDACL(t, repaired, testDACL(t, canonicalTestDACL), true)
		return CanonicalRepaired
	}
}

// GAP-0561: the service-pinned config.yaml gets its repair attempt first; a
// repair that leaves the Users writer in place is refused on standalone.
func TestStandaloneTrustRefusesConfigTheRepairCannotFix(t *testing.T) {
	path := trustedThenDriftedConfigForTest(t)
	calls := stubConfigRepairForTest(t, func(string) CanonicalOutcome { return CanonicalBoundary })
	if err := ValidateTrustedConfigPath(path); err == nil {
		t.Fatal("standalone accepted config.yaml that the repair could not fix")
	}
	if *calls != 1 {
		t.Fatalf("repair calls = %d, want 1", *calls)
	}
}

// Twin: ACL-only drift (the bytes are the ones last read while trusted) ends
// trusted and accepted on standalone once the repair fixed the descriptor.
func TestStandaloneTrustAcceptsConfigTheRepairFixed(t *testing.T) {
	path := trustedThenDriftedConfigForTest(t)
	calls := stubConfigRepairForTest(t, restampRepairForTest(t))
	if err := ValidateTrustedConfigPath(path); err != nil {
		t.Fatalf("standalone refused config.yaml after an ACL-only repair: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("repair calls = %d, want 1", *calls)
	}
	if err := ValidateTrustedFilePath(path, "managed config"); err != nil {
		t.Fatalf("config.yaml is not trusted after the repair: %v", err)
	}
}

// GAP-0561 review 1: a user who edited config.yaml through the write grant
// gains nothing from a repair. The edited bytes are refused with the strict
// verdict, and the file is left unrepaired so every other process refuses
// it too.
func TestStandaloneTrustRefusesConfigEditedBeforeRepair(t *testing.T) {
	path := trustedThenDriftedConfigForTest(t)
	if err := os.WriteFile(path, []byte("edited"), 0o600); err != nil {
		t.Fatalf("edit config.yaml: %v", err)
	}
	calls := stubConfigRepairForTest(t, restampRepairForTest(t))
	strict := ValidateTrustedFilePath(path, "managed config")
	err := ValidateTrustedConfigPath(path)
	if err == nil {
		t.Fatal("standalone accepted config.yaml a user edited before the repair")
	}
	if strict == nil || err.Error() != strict.Error() {
		t.Fatalf("standalone error = %v, want the strict verdict %v", err, strict)
	}
	if *calls != 0 {
		t.Fatalf("repair calls = %d, want none for unproven content", *calls)
	}
	if ValidateTrustedFilePath(path, "managed config") == nil {
		t.Fatal("the edited config.yaml was made to look trusted")
	}
}

// GAP-0561 review 2: the repair runs while no other handle can write the
// file, so a write during the repair fails and the proven bytes are the ones
// accepted.
func TestStandaloneTrustBlocksWritesDuringRepair(t *testing.T) {
	path := trustedThenDriftedConfigForTest(t)
	var writeErr error
	stubConfigRepairForTest(t, func(repaired string) CanonicalOutcome {
		writeErr = os.WriteFile(repaired, []byte("edited"), 0o600)
		setTestFileDACL(t, repaired, testDACL(t, canonicalTestDACL), true)
		return CanonicalRepaired
	})
	if err := ValidateTrustedConfigPath(path); err != nil {
		t.Fatalf("standalone refused an ACL-only repair: %v", err)
	}
	if writeErr == nil {
		t.Fatal("a write during the repair succeeded")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "ok" {
		t.Fatalf("config.yaml = %q, %v; want the proven bytes", got, err)
	}
}

// GAP-0561 review 2: a write handle opened during the drift keeps working
// after a DACL change. While it is open the repair does not run, and the
// file keeps the descriptor the strict check refuses, so a fresh process
// refuses it too; bytes written through it are refused, without a repair,
// after it closes.
func TestStandaloneTrustRefusesConfigWithRetainedWriteHandle(t *testing.T) {
	path := trustedThenDriftedConfigForTest(t)
	calls := stubConfigRepairForTest(t, restampRepairForTest(t))
	handle, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open a write handle during the drift: %v", err)
	}
	if err := ValidateTrustedConfigPath(path); err == nil {
		t.Fatal("standalone accepted config.yaml while another handle could write it")
	}
	if ValidateTrustedFilePath(path, "managed config") == nil {
		t.Fatal("config.yaml was made to look trusted while another handle could write it")
	}
	if _, err := handle.WriteAt([]byte("edited"), 0); err != nil {
		t.Fatalf("write through the retained handle: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTrustedConfigPath(path); err == nil {
		t.Fatal("standalone accepted bytes written through a retained handle")
	}
	if *calls != 0 {
		t.Fatalf("repair calls = %d, want none", *calls)
	}
	// A fresh process has no record of the trusted read and only the
	// descriptor, which still refuses.
	trustedContentDigests.Range(func(key, _ any) bool {
		trustedContentDigests.Delete(key)
		return true
	})
	if err := ValidateTrustedConfigPath(path); err == nil {
		t.Fatal("a fresh standalone process accepted the edited config.yaml")
	}
	if *calls != 0 {
		t.Fatalf("repair calls = %d, want none", *calls)
	}
}

// A process that never read config.yaml while it was trusted has no
// provenance for its bytes, so a drifted file is refused without a repair.
func TestStandaloneTrustRefusesDriftedConfigWithoutProvenance(t *testing.T) {
	path := driftedPolicyFileForTest(t, "config.yaml")
	pinTrustProfileForTest(t, true)
	t.Setenv(ConfigPathEnv, path)
	calls := stubConfigRepairForTest(t, restampRepairForTest(t))
	if err := ValidateTrustedConfigPath(path); err == nil {
		t.Fatal("standalone accepted drifted config.yaml with no trusted read")
	}
	if *calls != 0 {
		t.Fatalf("repair calls = %d, want none", *calls)
	}
}

// Twin: Secure Client keeps the 26.8.4 behaviour, accepting the drift the
// repair could not fix and logging it, edited bytes included.
func TestSecureClientTrustStillAcceptsAndLogsDrift(t *testing.T) {
	path := driftedPolicyFileForTest(t, "config.yaml")
	pinTrustProfileForTest(t, false)
	t.Setenv(ConfigPathEnv, path)
	if err := os.WriteFile(path, []byte("edited"), 0o600); err != nil {
		t.Fatalf("edit config.yaml: %v", err)
	}
	calls := stubConfigRepairForTest(t, func(string) CanonicalOutcome { return CanonicalBoundary })
	reports := captureTrustDrift(t)
	if err := ValidateTrustedConfigPath(path); err != nil {
		t.Fatalf("Secure Client refused drifted config.yaml: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("repair calls = %d, want 1", *calls)
	}
	if !reportsMention(*reports, path, "untrusted Windows principal") {
		t.Fatalf("drift reports = %v, want an untrusted-principal report for %s", *reports, path)
	}
	if err := ValidateTrustedPolicyFilePath(path, "hook guardian manifest"); err != nil {
		t.Fatalf("Secure Client refused a drifted policy file: %v", err)
	}
}

// The standalone scope follows the protected profile pin.
func TestWindowsStandaloneTrustScopeFollowsProfilePin(t *testing.T) {
	t.Setenv(EnterpriseProfileEnv, ProfileStandalone)
	if !windowsStandaloneTrustScope() {
		t.Fatal("the standalone profile pin did not select the standalone trust scope")
	}
	t.Setenv(EnterpriseProfileEnv, ProfileSecureClient)
	if StandaloneTrustScope() {
		t.Fatal("a Secure Client pin selected the standalone trust scope")
	}
}

// driftedRuntimeDirForTest is driftedPolicyFileForTest for a folder.
func driftedRuntimeDirForTest(t *testing.T) string {
	t.Helper()
	t.Setenv(TrustStrictAncestorsEnv, "")
	dir := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	setTestFileDACL(t, dir, testDACL(t, canonicalTestDACL), true)
	if err := ValidateTrustedRuntimeDir(dir, "fixture"); err != nil {
		t.Skipf("the process user does not own a trusted temp folder here: %v", err)
	}
	setTestFileDACL(t, dir, testDACL(t, usersWriteDACL), true)
	if err := ValidateTrustedRuntimeDir(dir, "fixture"); err == nil {
		t.Fatal("ValidateTrustedRuntimeDir accepted a Users writer; the strict API must be unchanged")
	}
	return dir
}

// GAP-0561: every drift-tolerant walk follows the profile, through
// windowsTrustScope.driftTolerated: the hook executable check and the
// tolerant folder check refuse drift on standalone and accept and log it on
// Secure Client. Once the drift is repaired both pass on standalone.
func TestStandaloneTrustGatesEveryDriftTolerantWalk(t *testing.T) {
	checks := []struct {
		name    string
		fixture func(*testing.T) string
		check   func(string) error
		strict  func(string) error
	}{
		{
			name:    "executable",
			fixture: func(t *testing.T) string { return driftedPolicyFileForTest(t, "defenseclaw-hook.exe") },
			check:   func(path string) error { return ValidateExecutableFilePath(path, "enterprise hook executable") },
			strict:  func(path string) error { return ValidateTrustedFilePath(path, "enterprise hook executable") },
		},
		{
			name:    "runtime dir",
			fixture: driftedRuntimeDirForTest,
			check:   func(path string) error { return ValidateTrustedRuntimeDirTolerant(path, "managed-hook state root") },
			strict:  func(path string) error { return ValidateTrustedRuntimeDir(path, "managed-hook state root") },
		},
	}
	for _, tc := range checks {
		t.Run(tc.name+"/standalone refuses", func(t *testing.T) {
			path := tc.fixture(t)
			pinTrustProfileForTest(t, true)
			_ = captureTrustDrift(t)
			err := tc.check(path)
			if err == nil {
				t.Fatalf("standalone accepted %s drift", tc.name)
			}
			if want := tc.strict(path); want == nil || err.Error() != want.Error() {
				t.Fatalf("standalone error = %q, want the strict verdict %v", err, want)
			}
		})
		t.Run(tc.name+"/secure client accepts and logs", func(t *testing.T) {
			path := tc.fixture(t)
			pinTrustProfileForTest(t, false)
			reports := captureTrustDrift(t)
			if err := tc.check(path); err != nil {
				t.Fatalf("Secure Client refused %s drift: %v", tc.name, err)
			}
			if !reportsMention(*reports, path, "untrusted Windows principal") {
				t.Fatalf("drift reports = %v, want an untrusted-principal report for %s", *reports, path)
			}
		})
		t.Run(tc.name+"/standalone accepts after repair", func(t *testing.T) {
			path := tc.fixture(t)
			pinTrustProfileForTest(t, true)
			setTestFileDACL(t, path, testDACL(t, canonicalTestDACL), true)
			if err := tc.check(path); err != nil {
				t.Fatalf("standalone refused %s after the drift was repaired: %v", tc.name, err)
			}
		})
	}
}

// A standalone gateway still reads its own token: the service runtime file
// gate falls back to the strict service check, which allows the gateway
// service as a writer, instead of the tolerant walk, which does not.
func TestStandaloneServiceRuntimeFileKeepsGatewayWriter(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	pinTrustProfileForTest(t, true)
	const account = `NT SERVICE\DefenseClawGatewayG561`
	sid, err := windowsVirtualServiceSID(account)
	if err != nil {
		t.Fatalf("windowsVirtualServiceSID: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	path := filepath.Join(dir, "hook-api-token")
	if err := os.WriteFile(path, []byte("token"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	gatewayWrites := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid.String() + ")"
	setTestFileDACL(t, dir, testDACL(t, gatewayWrites), true)
	setTestFileDACL(t, path, testDACL(t, gatewayWrites), true)
	if err := ValidateTrustedServiceRuntimeFilePath(path, "hook token", account); err != nil {
		t.Skipf("the process user does not own a trusted temp tree here: %v", err)
	}
	if err := AcceptServiceRuntimeFileDrift(path, "hook token", account); err != nil {
		t.Fatalf("standalone refused a gateway-writable token: %v", err)
	}
	setTestFileDACL(t, path, testDACL(t, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)"), true)
	if err := AcceptServiceRuntimeFileDrift(path, "hook token", account); err == nil {
		t.Fatal("standalone accepted a token with a Users writer")
	}
}

// inheritedCreateChildDirForTest returns a folder whose only extra entry is
// the container-only BUILTIN\Users create-child grant it inherits from its
// parent, the shape a folder takes after its protection is reset to inherit
// from C:\ProgramData.
func inheritedCreateChildDirForTest(t *testing.T) string {
	t.Helper()
	t.Setenv(TrustStrictAncestorsEnv, "")
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	setTestFileDACL(t, parent, testDACL(t, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;CI;0x1201bf;;;BU)"), true)
	dir := filepath.Join(parent, "policies")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	return dir
}

// GAP-0566: the normal walk's acceptance of an inherited Users create-child
// entry is the Secure Client rule. On standalone a standard user who can add
// a file to a folder whose every file is loaded changes what is enforced, so
// the folder is refused there.
func TestStandaloneTrustRefusesInheritedCreateChild(t *testing.T) {
	t.Run("secure client accepts", func(t *testing.T) {
		dir := inheritedCreateChildDirForTest(t)
		pinTrustProfileForTest(t, false)
		if err := ValidateTrustedRuntimeDir(dir, "policy folder"); err != nil {
			t.Fatalf("Secure Client refused the inherited create-child folder: %v", err)
		}
	})
	t.Run("standalone refuses", func(t *testing.T) {
		dir := inheritedCreateChildDirForTest(t)
		pinTrustProfileForTest(t, true)
		if err := ValidateTrustedRuntimeDir(dir, "policy folder"); err == nil {
			t.Fatal("standalone accepted a policy folder standard users can add files to")
		}
		if AcceptInheritedCreateChild(dir, "audit store", windows.INHERITED_ACE|windows.CONTAINER_INHERIT_ACE, 0x1201bf, usersSIDForTest(t)) {
			t.Fatal("standalone accepted an inherited create-child entry for the audit store and token folders")
		}
	})
}

func usersSIDForTest(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}
