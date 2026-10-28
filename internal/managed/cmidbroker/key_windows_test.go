// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmidbroker

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// testGatewaySID is a fixed NT SERVICE SID; the drift rules only compare it.
const testGatewaySID = "S-1-5-80-1111111111-2222222222-3333333333-4444444444-555555555"

func mustSID(t *testing.T, raw string) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid(raw)
	if err != nil {
		t.Fatalf("StringToSid(%q): %v", raw, err)
	}
	return sid
}

func driftFor(t *testing.T, sddl string, gatewaySID *windows.SID) []string {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString(%q): %v", sddl, err)
	}
	drift, err := keyDescriptorDrift(descriptor, gatewaySID)
	if err != nil {
		t.Fatalf("keyDescriptorDrift(%q): %v", sddl, err)
	}
	return drift
}

func TestKeyDescriptorDriftCanonicalIsClean(t *testing.T) {
	gateway := mustSID(t, testGatewaySID)
	for _, owner := range []string{"BA", "SY"} {
		sddl := "O:" + owner + "G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;" + testGatewaySID + ")"
		if drift := driftFor(t, sddl, gateway); len(drift) != 0 {
			t.Fatalf("canonical descriptor with owner %s reported drift %v", owner, drift)
		}
	}
}

func TestKeyDescriptorDriftReportsEachMismatch(t *testing.T) {
	gateway := mustSID(t, testGatewaySID)
	gatewayRead := "(A;;FR;;;" + testGatewaySID + ")"
	for _, test := range []struct {
		name string
		sddl string
		want string
	}{
		{
			name: "unprotected DACL",
			sddl: "O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)" + gatewayRead,
			want: "DACL is not protected",
		},
		{
			name: "fourth ACE",
			sddl: "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" + gatewayRead + "(A;;FR;;;BU)",
			want: "unexpected principal S-1-5-32-545",
		},
		{
			name: "missing gateway ACE",
			sddl: "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
			want: "gateway ACE is missing",
		},
		{
			name: "gateway ACE with write",
			sddl: "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFW;;;" + testGatewaySID + ")",
			want: "is not read-only",
		},
		{
			name: "untrusted owner",
			sddl: "O:S-1-5-21-1-2-3-1001G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" + gatewayRead,
			want: "owner S-1-5-21-1-2-3-1001 is not trusted",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			drift := driftFor(t, test.sddl, gateway)
			if len(drift) != 1 || !strings.Contains(drift[0], test.want) {
				t.Fatalf("drift = %v, want exactly one reason containing %q", drift, test.want)
			}
		})
	}
}

func TestKeyDescriptorDriftWithoutGatewaySID(t *testing.T) {
	if drift := driftFor(t, "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", nil); len(drift) != 0 {
		t.Fatalf("missing gateway ACE reported without a gateway SID: %v", drift)
	}
	// The installed gateway ACE is presumed to be the read-only NT SERVICE ACE.
	if drift := driftFor(t, "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;"+testGatewaySID+")", nil); len(drift) != 0 {
		t.Fatalf("read-only NT SERVICE ACE reported without a gateway SID: %v", drift)
	}
	if drift := driftFor(t, "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)", nil); len(drift) != 1 {
		t.Fatalf("Users ACE without a gateway SID: drift = %v, want one reason", drift)
	}
}

// writeTestKey writes a 32-byte key under a fresh temp directory and stamps
// sddl's DACL on it. The test process owns the file, so no elevation is needed
// unless the descriptor changes the owner.
func writeTestKey(t *testing.T, sddl string, protected bool) (string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "broker-auth.key")
	want := bytes.Repeat([]byte{0x5a}, AuthKeyBytes)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if protected {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo: %v", err)
	}
	return path, want
}

func fileSDDL(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	return descriptor.String()
}

type recordedReports []KeyDriftReport

func (reports *recordedReports) policy(repair bool) KeyDriftPolicy {
	return KeyDriftPolicy{Repair: repair, Report: func(report KeyDriftReport) {
		*reports = append(*reports, report)
	}}
}

func (reports recordedReports) actions() []string {
	actions := make([]string, 0, len(reports))
	for _, report := range reports {
		actions = append(actions, report.Action)
	}
	return actions
}

// quietTrustWalk keeps the ancestor drift advisories from the temp tree out of
// the test log; they are not what these tests assert.
func quietTrustWalk(t *testing.T) {
	t.Helper()
	previous := managed.ReportTrustDrift
	managed.ReportTrustDrift = func(string, string, string) {}
	t.Cleanup(func() { managed.ReportTrustDrift = previous })
}

func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires an elevated test process")
	}
}

// driftedKeySDDL grants the test owner full access through an inheritable,
// unprotected DACL: the shape a parent re-ACL leaves behind.
const driftedKeySDDL = "D:(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"

func TestLoadAuthKeyRepairsDriftedDescriptor(t *testing.T) {
	requireElevated(t)
	quietTrustWalk(t)
	path, want := writeTestKey(t, driftedKeySDDL, false)
	var reports recordedReports
	key, err := LoadAuthKey(path, defaultGatewayService, reports.policy(true))
	if err != nil {
		t.Fatalf("LoadAuthKey: %v", err)
	}
	if !bytes.Equal(key[:], want) {
		t.Fatal("LoadAuthKey returned the wrong key bytes")
	}
	if len(reports) != 1 || reports[0].Action != KeyDriftRepaired || reports[0].RepairError != "" {
		t.Fatalf("reports = %+v, want exactly one repaired report", reports)
	}
	gatewaySID, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + defaultGatewayService)
	if err != nil {
		t.Fatalf("resolve gateway SID: %v", err)
	}
	// Compare meaning, not SDDL text: Windows may add SE_DACL_AUTO_INHERITED
	// (D:PAI) when it applies a protected DACL.
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	if drift, err := keyDescriptorDrift(descriptor, gatewaySID); err != nil || len(drift) != 0 {
		t.Fatalf("repaired descriptor %s still drifts: %v (err %v)", descriptor, drift, err)
	}
	// An elevated test process usually creates files owned by Administrators,
	// which the repair keeps; a user-owned file is moved to Administrators.
	// Either way the repaired owner is trusted.
	if owner, _, err := descriptor.Owner(); err != nil || !trustedKeyOwner(owner) {
		t.Fatalf("repaired owner = %v (err %v), want SYSTEM or Administrators", owner, err)
	}

	// A second load sees a clean key and reports nothing.
	reports = nil
	if _, err := LoadAuthKey(path, defaultGatewayService, reports.policy(true)); err != nil {
		t.Fatalf("LoadAuthKey after repair: %v", err)
	}
	if len(reports) != 0 {
		t.Fatalf("reports after repair = %+v, want none", reports)
	}
}

func TestLoadAuthKeyWithoutRepairAcceptsDrift(t *testing.T) {
	quietTrustWalk(t)
	path, want := writeTestKey(t, driftedKeySDDL, false)
	before := fileSDDL(t, path)
	var reports recordedReports
	key, err := LoadAuthKey(path, defaultGatewayService, reports.policy(false))
	if err != nil {
		t.Fatalf("LoadAuthKey: %v", err)
	}
	if !bytes.Equal(key[:], want) {
		t.Fatal("LoadAuthKey returned the wrong key bytes")
	}
	if got := fileSDDL(t, path); got != before {
		t.Fatalf("descriptor changed without repair: %s -> %s", before, got)
	}
	if len(reports) != 1 || reports[0].Action != KeyDriftAccepted || reports[0].RepairError != "" {
		t.Fatalf("reports = %+v, want exactly one accepted report", reports)
	}
	if !strings.Contains(reports[0].Reason, "DACL is not protected") {
		t.Fatalf("accepted reason = %q, want the unprotected DACL named", reports[0].Reason)
	}
}

func TestLoadAuthKeyFailedRepairIsAccepted(t *testing.T) {
	quietTrustWalk(t)
	var requested uint32
	previous := openKeyForRepair
	openKeyForRepair = func(_ *uint16, access uint32) (windows.Handle, error) {
		requested = access
		return windows.InvalidHandle, windows.ERROR_ACCESS_DENIED
	}
	t.Cleanup(func() { openKeyForRepair = previous })

	path, want := writeTestKey(t, driftedKeySDDL, false)
	// The repair asks for WRITE_OWNER only when the current owner is not
	// trusted; a SYSTEM- or Administrators-owned key keeps its owner.
	owned, _, err := mustOwner(t, path)
	if err != nil {
		t.Fatal(err)
	}
	wantOwnerRight := !trustedKeyOwner(owned)
	var reports recordedReports
	key, err := LoadAuthKey(path, defaultGatewayService, reports.policy(true))
	if err != nil {
		t.Fatalf("LoadAuthKey: %v", err)
	}
	if !bytes.Equal(key[:], want) {
		t.Fatal("LoadAuthKey returned the wrong key bytes")
	}
	if len(reports) != 1 || reports[0].Action != KeyDriftAccepted ||
		!strings.Contains(reports[0].RepairError, windows.ERROR_ACCESS_DENIED.Error()) {
		t.Fatalf("reports = %+v, want one accepted report carrying the repair error", reports)
	}
	if requested&windows.WRITE_DAC == 0 {
		t.Fatalf("repair access 0x%x lacks WRITE_DAC", requested)
	}
	if gotOwnerRight := requested&windows.WRITE_OWNER != 0; gotOwnerRight != wantOwnerRight {
		t.Fatalf("repair requested WRITE_OWNER=%t for owner %s, want %t", gotOwnerRight, owned, wantOwnerRight)
	}
}

func mustOwner(t *testing.T, path string) (*windows.SID, *windows.SECURITY_DESCRIPTOR, error) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, nil, err
	}
	owner, _, err := descriptor.Owner()
	return owner, descriptor, err
}

func TestTrustedKeyOwner(t *testing.T) {
	for raw, want := range map[string]bool{
		"S-1-5-18":            true,  // SYSTEM
		"S-1-5-32-544":        true,  // Administrators
		"S-1-5-21-1-2-3-1001": false, // a user
		testGatewaySID:        false, // the gateway reads the key; it never owns it
	} {
		if got := trustedKeyOwner(mustSID(t, raw)); got != want {
			t.Errorf("trustedKeyOwner(%s) = %t, want %t", raw, got, want)
		}
	}
	if trustedKeyOwner(nil) {
		t.Error("nil owner reported as trusted")
	}
}

func TestLoadAuthKeyStrictPinKeepsDriftFatal(t *testing.T) {
	quietTrustWalk(t)
	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	path, _ := writeTestKey(t, driftedKeySDDL, false)
	var reports recordedReports
	if _, err := LoadAuthKey(path, defaultGatewayService, reports.policy(true)); err == nil {
		t.Fatal("strict pin accepted a drifted key")
	}
	if len(reports) != 0 {
		t.Fatalf("reports under strict pin = %+v, want none", reports)
	}
}

func TestLoadAuthKeyStructuralFailuresStayFatal(t *testing.T) {
	quietTrustWalk(t)
	const sddl = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"

	t.Run("short key", func(t *testing.T) {
		path, _ := writeTestKey(t, sddl, true)
		if err := os.Truncate(path, AuthKeyBytes-1); err != nil {
			t.Fatalf("Truncate: %v", err)
		}
		var reports recordedReports
		if _, err := LoadAuthKey(path, defaultGatewayService, reports.policy(false)); err == nil ||
			!strings.Contains(err.Error(), "invalid length") {
			t.Fatalf("31-byte key error = %v, want invalid length", err)
		}
	})

	t.Run("hard link", func(t *testing.T) {
		path, _ := writeTestKey(t, sddl, true)
		if err := os.Link(path, path+".link"); err != nil {
			t.Skipf("hard link creation unavailable: %v", err)
		}
		var reports recordedReports
		if _, err := LoadAuthKey(path, defaultGatewayService, reports.policy(false)); err == nil ||
			!strings.Contains(err.Error(), "unsafe file type") {
			t.Fatalf("hard-linked key error = %v, want unsafe file type", err)
		}
	})

	t.Run("reparse point", func(t *testing.T) {
		target, _ := writeTestKey(t, sddl, true)
		link := filepath.Join(t.TempDir(), "broker-auth.key")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		var reports recordedReports
		if _, err := LoadAuthKey(link, defaultGatewayService, reports.policy(false)); err == nil {
			t.Fatal("symlinked key accepted")
		}
	})

	t.Run("reporter required", func(t *testing.T) {
		path, _ := writeTestKey(t, sddl, true)
		if _, err := LoadAuthKey(path, defaultGatewayService, KeyDriftPolicy{}); err == nil {
			t.Fatal("LoadAuthKey ran without a drift reporter")
		}
	})
}
