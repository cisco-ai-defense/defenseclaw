//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
			if !strings.HasPrefix(err.Error(), strict.Error()) {
				t.Fatalf("standalone error = %q, want the strict verdict %q", err, strict)
			}
			var principal *UntrustedPrincipalError
			if !errors.As(err, &principal) {
				t.Fatalf("standalone error %v does not carry the untrusted principal", err)
			}
		})
	}
}

// openRetainedHandleForTest opens path the way a standard user holding a
// drift grant would, with full sharing so a trusted rewrite can still replace
// the name, and returns the handle.
func openRetainedHandleForTest(t *testing.T, path string, access uint32) windows.Handle {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pointer, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("open retained handle: %v", err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	return handle
}

// trustedRewriteForTest is what Setup does with [IO.File]::Replace: a fresh
// file under the canonical descriptor takes the name, and the old file moves
// to a backup name, so a handle to the old file points at the replaced
// object. ReplaceFile renames the open old file aside in the same way.
func trustedRewriteForTest(t *testing.T, path string, content []byte) {
	t.Helper()
	fresh := path + ".setup"
	if err := os.WriteFile(fresh, content, 0o600); err != nil {
		t.Fatal(err)
	}
	setTestFileDACL(t, fresh, testDACL(t, canonicalTestDACL), true)
	move := func(from, to string) {
		t.Helper()
		source, err := windows.UTF16PtrFromString(from)
		if err != nil {
			t.Fatal(err)
		}
		target, err := windows.UTF16PtrFromString(to)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.MoveFileEx(source, target, windows.MOVEFILE_WRITE_THROUGH); err != nil {
			t.Fatalf("move %s to %s: %v", from, to, err)
		}
	}
	move(path, path+".backup")
	move(fresh, path)
}

// GAP-0561 review 3: on standalone a drifted config.yaml is never repaired in
// place, not even the service-pinned one; it is refused with the strict
// verdict plus what to run, and keeps the descriptor every process refuses.
func TestStandaloneTrustNeverRepairsDriftedConfigInPlace(t *testing.T) {
	path := driftedPolicyFileForTest(t, "config.yaml")
	pinTrustProfileForTest(t, true)
	t.Setenv(ConfigPathEnv, path)
	calls := stubConfigRepairForTest(t, func(repaired string) CanonicalOutcome {
		setTestFileDACL(t, repaired, testDACL(t, canonicalTestDACL), true)
		return CanonicalRepaired
	})
	err := ValidateTrustedConfigPath(path)
	if err == nil {
		t.Fatal("standalone accepted a drifted config.yaml")
	}
	if !strings.Contains(err.Error(), "Setup /ensure") {
		t.Fatalf("standalone refusal %q does not say how to recover", err)
	}
	if *calls != 0 {
		t.Fatalf("repair calls = %d, want none on standalone", *calls)
	}
	if ValidateTrustedFilePath(path, "managed config") == nil {
		t.Fatal("the drifted config.yaml was made to look trusted")
	}
}

// GAP-0561 review 3: writes through a write or WRITE_DAC handle opened
// during the drift leave the file refused while the drift is in place. Only a
// trusted rewrite recovers it, and a handle to the old file cannot change the
// new one.
func TestStandaloneTrustRecoversOnlyThroughTrustedRewrite(t *testing.T) {
	path := driftedPolicyFileForTest(t, "config.yaml")
	pinTrustProfileForTest(t, true)
	t.Setenv(ConfigPathEnv, path)
	calls := stubConfigRepairForTest(t, func(string) CanonicalOutcome { return CanonicalRepaired })
	writer := openRetainedHandleForTest(t, path, windows.GENERIC_READ|windows.GENERIC_WRITE)
	dacl := openRetainedHandleForTest(t, path, windows.READ_CONTROL|windows.WRITE_DAC)
	var written uint32
	if err := windows.WriteFile(writer, []byte("edited"), &written, nil); err != nil {
		t.Fatalf("write through the retained handle: %v", err)
	}
	everyone := testDACL(t, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)")
	if err := windows.SetSecurityInfo(dacl, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, everyone, nil); err != nil {
		t.Fatalf("regrant through the retained WRITE_DAC handle: %v", err)
	}
	if err := ValidateTrustedConfigPath(path); err == nil {
		t.Fatal("standalone accepted config.yaml after writes through retained handles")
	}

	trustedRewriteForTest(t, path, []byte("approved"))
	if err := ValidateTrustedConfigPath(path); err != nil {
		t.Fatalf("standalone refused config.yaml after a trusted rewrite: %v", err)
	}
	if err := windows.WriteFile(writer, []byte("late edit"), &written, nil); err != nil {
		t.Fatalf("write through the old handle: %v", err)
	}
	if err := windows.SetSecurityInfo(dacl, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, everyone, nil); err != nil {
		t.Fatalf("regrant through the old WRITE_DAC handle: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "approved" {
		t.Fatalf("config.yaml = %q, %v after old-handle writes; want the rewritten bytes", got, err)
	}
	if err := ValidateTrustedConfigPath(path); err != nil {
		t.Fatalf("an old handle changed the rewritten config.yaml: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("repair calls = %d, want none on standalone", *calls)
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
	// GAP-0566 review 2: inside the Cisco root the exported helper still
	// needs a verified Secure Client host; an OSS data_dir there is refused.
	t.Run("inside the installer roots it needs a verified Secure Client host", func(t *testing.T) {
		base := t.TempDir()
		t.Cleanup(AddTrustedMachineInstallBaseForTest(base))
		t.Setenv(TrustStrictAncestorsEnv, "")
		pinTrustProfileForTest(t, false)
		dir := filepath.Join(base, "Cisco", "oss-data", "audit")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if !PlatformInstallerOwnedPath(dir) {
			t.Fatal("the test folder is not inside the stand-in Cisco root")
		}
		previous := SecureClientHostVerified
		t.Cleanup(func() { SecureClientHostVerified = previous })
		flags := uint8(windows.INHERITED_ACE | windows.CONTAINER_INHERIT_ACE)
		SecureClientHostVerified = func() bool { return false }
		if AcceptInheritedCreateChild(dir, "audit store", flags, 0x1201bf, usersSIDForTest(t)) {
			t.Fatal("an OSS audit folder under the Cisco root accepted an inherited create-child entry")
		}
		SecureClientHostVerified = func() bool { return true }
		if !AcceptInheritedCreateChild(dir, "audit store", flags, 0x1201bf, usersSIDForTest(t)) {
			t.Fatal("a verified Secure Client host refused the inherited create-child entry under the Cisco root")
		}
	})
	// GAP-0566 review 1: the audit store, judge-body and hook token walks
	// accept the entry only inside the platform installer's roots, so a
	// per-user data_dir elsewhere under ProgramData is refused on every
	// profile.
	t.Run("outside the installer roots the exported helper refuses", func(t *testing.T) {
		dir := inheritedCreateChildDirForTest(t)
		pinTrustProfileForTest(t, false)
		if PlatformInstallerOwnedPath(dir) {
			t.Skip("the test temp folder is inside the platform installer roots")
		}
		if AcceptInheritedCreateChild(dir, "audit store", windows.INHERITED_ACE|windows.CONTAINER_INHERIT_ACE, 0x1201bf, usersSIDForTest(t)) {
			t.Fatal("an inherited create-child entry was accepted for an audit folder outside the installer roots")
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
