// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// The Windows fixture of the key custody tests (rel-1-0-10:GAP-1514,
// GAP-1515). The custody accepts a managed data_dir only when an installer
// principal owns it and only the gateway service can write it besides
// LocalSystem and Administrators, and it hands every credential file to that
// service SID. So the data_dir is an Administrators-owned folder under a test
// ProgramData (testenv.CiscoRuntimeTree: run elevated), and the gateway
// service account is pinned to NT SERVICE\TrustedInstaller, whose service SID
// resolves on every Windows host.

// enterpriseHookTestKeyRotationStages: the Windows lifecycle never stages a
// next per-user credential key (loadEnterpriseHookPendingUserTokenKey), so a
// staged key file is never rendered from in any phase.
const enterpriseHookTestKeyRotationStages = false

func enterpriseHookTokenTestDataDir(t *testing.T) string {
	t.Helper()
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\TrustedInstaller`)
	_, root := testenv.CiscoRuntimeTree(t, "DefenseClaw")
	return root
}

// enterpriseHookTestUserIdentities are two user SIDs: the Windows guardian
// binds per-user credentials to the target's SID.
func enterpriseHookTestUserIdentities() (string, string) {
	return "S-1-5-21-100-200-300-1001", "S-1-5-21-100-200-300-1002"
}

// publishEnterpriseHookTestRouteEpoch stands in for the gateway, which
// publishes the route epoch every Windows route credential is derived with.
func publishEnterpriseHookTestRouteEpoch(t *testing.T, dataDir string) *connector.RouteEpoch {
	t.Helper()
	epoch, err := connector.NewRouteEpoch()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(epoch)
	if err != nil {
		t.Fatal(err)
	}
	path, err := connector.RouteEpochPath(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	testenv.WriteAdminOnlyFile(t, path, raw)
	return &epoch
}

// assertEnterpriseHookSecretCustody is the Windows form of the 0600 check:
// the custody accepts the file, an installer principal or the gateway service
// owns it, its DACL is protected, the gateway service SID can read it, and no
// one else has any entry (no Everyone, Users, Authenticated Users or other
// account entry, inherited or explicit).
func assertEnterpriseHookSecretCustody(t *testing.T, dataDir, path, label string) {
	t.Helper()
	if err := validateEnterpriseWindowsTokenLocation(dataDir, path, label); err != nil {
		t.Fatalf("%s custody refused: %v", label, err)
	}
	serviceSID, err := enterpriseWindowsGatewayServiceSID()
	if err != nil {
		t.Fatal(err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("%s descriptor: %v", label, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if !enterpriseWindowsRuntimeRepairOwnerTrusted(owner, serviceSID) {
		t.Fatalf("%s owner %v is not an installer principal or the gateway service", label, owner)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("%s DACL is not protected: it inherits its folder's entries", label)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s has no DACL: %v", label, err)
	}
	serviceReads := false
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case windows.ACCESS_DENIED_ACE_TYPE:
			// A deny entry grants nothing.
			continue
		default:
			// Callback, object and any other allowed type could grant another account: do not let it pass unread.
			t.Fatalf("%s has an entry of ACE type %d: only plain allowed and denied entries are expected", label, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(serviceSID):
			serviceReads = serviceReads || ace.Mask&windows.FILE_READ_DATA != 0
		case sid.Equals(owner), sid.IsWellKnown(windows.WinLocalSystemSid), sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
		default:
			t.Fatalf("%s grants %s access mask 0x%x: only the owner, LocalSystem, Administrators and the gateway service may have an entry", label, sid, uint32(ace.Mask))
		}
	}
	if !serviceReads {
		t.Fatalf("%s: the gateway service SID cannot read it", label)
	}
}
