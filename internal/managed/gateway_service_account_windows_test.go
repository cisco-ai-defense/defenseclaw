//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const (
	productionGatewayAccountForTest    = `NT SERVICE\` + StandaloneWindowsGatewaySvc
	certificationGatewayServiceForTest = "DefenseClawCertGateway_0a1b2c3d4e"
	certificationGatewayAccountForTest = `NT SERVICE\` + certificationGatewayServiceForTest
)

// installServiceForTest pins the install root the running binary sits in.
func installServiceForTest(t *testing.T, service string) {
	t.Helper()
	previous := windowsStandaloneInstallService
	t.Cleanup(func() { windowsStandaloneInstallService = previous })
	windowsStandaloneInstallService = func() string { return service }
}

func TestStandaloneGatewayServiceNameMatchesTheInstallerLayout(t *testing.T) {
	if winpath.EnterpriseGatewayServiceName != StandaloneWindowsGatewaySvc {
		t.Fatalf("winpath gateway service %q differs from the standalone layout %q",
			winpath.EnterpriseGatewayServiceName, StandaloneWindowsGatewaySvc)
	}
}

func TestGatewayServiceForExecutableFollowsTheInstallRoot(t *testing.T) {
	roots, err := winpath.EnterpriseRootsFor(winpath.EnterpriseProfileStandalone, `C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		executable string
		want       string
	}{
		{"production root", `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe`, StandaloneWindowsGatewaySvc},
		{"production root, other case", `c:\program files\cisco\defenseclaw\BIN\defenseclaw.exe`, StandaloneWindowsGatewaySvc},
		{"certification root", `C:\Program Files\Cisco\DefenseClaw-Cert\0a1b2c3d4e\bin\defenseclaw.exe`, certificationGatewayServiceForTest},
		{"certification root, other run", `C:\Program Files\Cisco\DefenseClaw-Cert\ffffffffff\bin\defenseclaw.exe`, "DefenseClawCertGateway_ffffffffff"},
		// Twins: nothing outside an exact install root's bin folder names a service.
		{"certification base itself", `C:\Program Files\Cisco\DefenseClaw-Cert\bin\defenseclaw.exe`, ""},
		{"certification run id not hex", `C:\Program Files\Cisco\DefenseClaw-Cert\0A1B2C3D4E\bin\defenseclaw.exe`, ""},
		{"not in a bin folder", `C:\Program Files\Cisco\DefenseClaw\libexec\defenseclaw.exe`, ""},
		{"copied binary", `C:\Users\Public\DefenseClaw\bin\defenseclaw.exe`, ""},
		{"secure client tree", `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\bin\defenseclaw.exe`, ""},
		{"relative path", `bin\defenseclaw.exe`, ""},
	} {
		if got := gatewayServiceForExecutable(tc.executable, roots); got != tc.want {
			t.Errorf("%s: gatewayServiceForExecutable(%q) = %q, want %q", tc.name, tc.executable, got, tc.want)
		}
	}
}

func TestGatewayServiceAccountFollowsPinThenInstallRoot(t *testing.T) {
	t.Run("pin wins", func(t *testing.T) {
		installServiceForTest(t, StandaloneWindowsGatewaySvc)
		t.Setenv(WindowsServiceAccountEnv, `NT SERVICE\OtherGateway`)
		if got := GatewayServiceAccount(); got != `NT SERVICE\OtherGateway` {
			t.Fatalf("GatewayServiceAccount() = %q, want the pinned account", got)
		}
	})
	t.Run("production console without the pin", func(t *testing.T) {
		installServiceForTest(t, StandaloneWindowsGatewaySvc)
		t.Setenv(WindowsServiceAccountEnv, "")
		if got := GatewayServiceAccount(); got != productionGatewayAccountForTest {
			t.Fatalf("GatewayServiceAccount() = %q, want %q", got, productionGatewayAccountForTest)
		}
	})
	t.Run("certification console without the pin", func(t *testing.T) {
		installServiceForTest(t, certificationGatewayServiceForTest)
		t.Setenv(WindowsServiceAccountEnv, "")
		if got := GatewayServiceAccount(); got != certificationGatewayAccountForTest {
			t.Fatalf("GatewayServiceAccount() = %q, want %q", got, certificationGatewayAccountForTest)
		}
	})
	// Twin: an unpinned process outside every install root (Secure Client, a
	// copied binary), even one that carries the standalone profile pin, keeps
	// the administrator-only rule.
	t.Run("outside every install root", func(t *testing.T) {
		installServiceForTest(t, "")
		t.Setenv(WindowsServiceAccountEnv, "")
		t.Setenv(EnterpriseProfileEnv, ProfileStandalone)
		if got := GatewayServiceAccount(); got != "" {
			t.Fatalf("GatewayServiceAccount() = %q, want no account outside an install root", got)
		}
	})
}

// GAP-0081: a runtime state file the gateway service rewrites carries the
// Modify entry (0x1301bf) the service holds on its runtime folder, inherited.
// A console without the service pin refused it. The service of the console's
// own install root is a trusted writer of that root's state; no other service
// (the other scope's gateway included), user or group with write-like access
// is.
func TestRuntimeStateReaderTrustsOnlyTheScopeGatewayServiceWriter(t *testing.T) {
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
	modify := func(sid string) string { return "(A;ID;0x1301bf;;;" + sid + ")" }
	admins := "(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
	productionSID := WindowsServiceSIDString(StandaloneWindowsGatewaySvc)
	certificationSID := WindowsServiceSIDString(certificationGatewayServiceForTest)

	for _, scope := range []struct {
		name    string
		service string
		own     string
		other   string
	}{
		{"production console", StandaloneWindowsGatewaySvc, productionSID, certificationSID},
		{"certification console", certificationGatewayServiceForTest, certificationSID, productionSID},
	} {
		t.Run(scope.name, func(t *testing.T) {
			installServiceForTest(t, scope.service)
			t.Setenv(WindowsServiceAccountEnv, "")
			if err := check(t, dacl(t, "D:"+modify(scope.own)+admins)); err != nil {
				t.Fatalf("refused the scope's own gateway service Modify entry: %v", err)
			}
			if err := check(t, dacl(t, "D:"+modify(scope.own)+admins+"(A;;0x1301bf;;;S-1-5-21-1-2-3-1001)")); err == nil {
				t.Fatal("a user SID with write-like access was accepted next to the service entry")
			}
			if err := check(t, dacl(t, "D:"+modify("S-1-5-80-9-8-7-6-5")+"(A;ID;FA;;;SY)")); err == nil {
				t.Fatal("a foreign service SID with write-like access was accepted")
			}
			if err := check(t, dacl(t, "D:"+modify(scope.other)+admins)); err == nil {
				t.Fatal("the other scope's gateway service SID was accepted as the writer")
			}
		})
	}

	t.Run("outside every install root", func(t *testing.T) {
		installServiceForTest(t, "")
		t.Setenv(WindowsServiceAccountEnv, "")
		if err := check(t, dacl(t, "D:"+modify(productionSID)+admins)); err == nil {
			t.Fatal("an unpinned process outside every install root accepted a service writer")
		}
	})
}
