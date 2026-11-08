//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"testing"

	"golang.org/x/sys/windows"
)

const gatewayAccountForTest = `NT SERVICE\` + StandaloneWindowsGatewaySvc

func TestGatewayServiceAccountFollowsPinThenStandaloneScope(t *testing.T) {
	t.Run("pin wins", func(t *testing.T) {
		pinTrustProfileForTest(t, true)
		t.Setenv(WindowsServiceAccountEnv, `NT SERVICE\OtherGateway`)
		if got := GatewayServiceAccount(); got != `NT SERVICE\OtherGateway` {
			t.Fatalf("GatewayServiceAccount() = %q, want the pinned account", got)
		}
	})
	t.Run("standalone console without the pin", func(t *testing.T) {
		pinTrustProfileForTest(t, true)
		t.Setenv(WindowsServiceAccountEnv, "")
		if got := GatewayServiceAccount(); got != gatewayAccountForTest {
			t.Fatalf("GatewayServiceAccount() = %q, want %q", got, gatewayAccountForTest)
		}
	})
	// Twin: an unpinned process outside the standalone scope (Secure Client,
	// a copied binary) keeps the administrator-only rule.
	t.Run("secure client without the pin", func(t *testing.T) {
		pinTrustProfileForTest(t, false)
		t.Setenv(WindowsServiceAccountEnv, "")
		if got := GatewayServiceAccount(); got != "" {
			t.Fatalf("GatewayServiceAccount() = %q, want no account outside the standalone scope", got)
		}
	})
}

// GAP-0081: the guardian state file the gateway service rewrites carries the
// Modify entry (0x1301bf) the service holds on runtime\, inherited. A console
// without the service pin refused it. The service SID is a trusted writer of
// its own state; any other principal with write-like access still is not.
func TestRuntimeStateReaderTrustsOnlyTheGatewayServiceWriter(t *testing.T) {
	serviceSID := WindowsServiceSIDString(StandaloneWindowsGatewaySvc)
	dacl := func(t *testing.T, sddl string) *windows.ACL {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatalf("SecurityDescriptorFromString: %v", err)
		}
		acl, _, err := descriptor.DACL()
		if err != nil || acl == nil {
			t.Fatalf("DACL: %v", err)
		}
		return acl
	}
	check := func(t *testing.T, acl *windows.ACL) error {
		t.Helper()
		writer, err := windowsVirtualServiceSID(GatewayServiceAccount())
		if err != nil {
			t.Fatalf("resolve the service account: %v", err)
		}
		return rejectUntrustedWindowsWriteACEsWithWriter("opencode_port_warnings.json", "hook guardian state", acl, writer, windowsTrustLeaf)
	}
	serviceModify := "(A;ID;0x1301bf;;;" + serviceSID + ")(A;ID;FA;;;SY)(A;ID;FA;;;BA)"

	pinTrustProfileForTest(t, true)
	t.Setenv(WindowsServiceAccountEnv, "")
	if err := check(t, dacl(t, "D:"+serviceModify)); err != nil {
		t.Fatalf("standalone console refused the gateway service Modify entry: %v", err)
	}
	if err := check(t, dacl(t, "D:"+serviceModify+"(A;;0x1301bf;;;S-1-5-21-1-2-3-1001)")); err == nil {
		t.Fatal("a user SID with write-like access was accepted next to the service entry")
	}
	if err := check(t, dacl(t, "D:(A;ID;0x1301bf;;;S-1-5-80-9-8-7-6-5)(A;ID;FA;;;SY)")); err == nil {
		t.Fatal("a foreign service SID with write-like access was accepted")
	}

	pinTrustProfileForTest(t, false)
	if err := check(t, dacl(t, "D:"+serviceModify)); err == nil {
		t.Fatal("an unpinned process outside the standalone scope accepted the service writer")
	}
}
