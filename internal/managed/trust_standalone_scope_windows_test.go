//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"testing"
)

// usersWriteDACL grants BUILTIN\Users write: drift no standard user may hold.
const usersWriteDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FW;;;BU)"

// canonicalTestDACL is the repaired form: SYSTEM, Administrators, the owner.
const canonicalTestDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"

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

// GAP-0561: the service-pinned config.yaml gets its repair attempt first; a
// repair that leaves the Users writer in place is refused on standalone.
func TestStandaloneTrustRefusesConfigTheRepairCannotFix(t *testing.T) {
	path := driftedPolicyFileForTest(t, "config.yaml")
	pinTrustProfileForTest(t, true)
	t.Setenv(ConfigPathEnv, path)
	calls := stubConfigRepairForTest(t, func(string) CanonicalOutcome { return CanonicalBoundary })
	if err := ValidateTrustedConfigPath(path); err == nil {
		t.Fatal("standalone accepted config.yaml that the repair could not fix")
	}
	if *calls != 1 {
		t.Fatalf("repair calls = %d, want 1", *calls)
	}
}

// Twin: a repair that does fix the drift ends trusted and accepted on
// standalone, because the strict check runs again after it.
func TestStandaloneTrustAcceptsConfigTheRepairFixed(t *testing.T) {
	path := driftedPolicyFileForTest(t, "config.yaml")
	pinTrustProfileForTest(t, true)
	t.Setenv(ConfigPathEnv, path)
	calls := stubConfigRepairForTest(t, func(repaired string) CanonicalOutcome {
		setTestFileDACL(t, repaired, testDACL(t, canonicalTestDACL), true)
		return CanonicalRepaired
	})
	if err := ValidateTrustedConfigPath(path); err != nil {
		t.Fatalf("standalone refused config.yaml after a successful repair: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("repair calls = %d, want 1", *calls)
	}
	if err := ValidateTrustedFilePath(path, "managed config"); err != nil {
		t.Fatalf("config.yaml is not trusted after the repair: %v", err)
	}
}

// Twin: Secure Client keeps the 26.8.4 behaviour, accepting the drift the
// repair could not fix and logging it.
func TestSecureClientTrustStillAcceptsAndLogsDrift(t *testing.T) {
	path := driftedPolicyFileForTest(t, "config.yaml")
	pinTrustProfileForTest(t, false)
	t.Setenv(ConfigPathEnv, path)
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
