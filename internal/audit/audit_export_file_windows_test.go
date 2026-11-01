//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

func TestManagedAuditExportUsesCanonicalDACLForAnAdministrator(t *testing.T) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		t.Fatalf("resolve current user SID: %v", err)
	}
	const serviceName = "DefenseClawCertGateway_Export"
	t.Setenv(connector.WindowsGatewayServiceNameEnv, serviceName)
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\`+serviceName)
	previousSID := auditDBWindowsServiceAccountSID
	previousRunsAs := auditDBWindowsCurrentProcessRunsAsService
	auditDBWindowsServiceAccountSID = func(string) (*windows.SID, error) { return current.User.Sid, nil }
	auditDBWindowsCurrentProcessRunsAsService = func(*windows.SID) (bool, error) { return false, nil }
	t.Cleanup(func() {
		auditDBWindowsServiceAccountSID = previousSID
		auditDBWindowsCurrentProcessRunsAsService = previousRunsAs
	})
	path := filepath.Join(t.TempDir(), "export.jsonl")
	file, err := CreateExportFileExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := auditDBWindowsManagedRuntimeFileCanonical(sd, current.User.Sid)
	if err != nil || !canonical {
		t.Fatalf("managed export DACL canonical = %v, %v", canonical, err)
	}
}

// GAP-1399: under LocalSystem the token owner is S-1-5-18, which the managed
// canonical check refuses, so every SYSTEM export of a managed store failed
// and its file was removed. The export is owned by Administrators instead.
func TestManagedAuditExportAsLocalSystemIsCanonical(t *testing.T) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		t.Fatalf("resolve current user SID: %v", err)
	}
	const serviceName = "DefenseClawCertGateway_ExportSystem"
	t.Setenv(connector.WindowsGatewayServiceNameEnv, serviceName)
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\`+serviceName)
	previousSID := auditDBWindowsServiceAccountSID
	previousRunsAs := auditDBWindowsCurrentProcessRunsAsService
	previousOwner := auditExportWindowsTokenOwner
	auditDBWindowsServiceAccountSID = func(string) (*windows.SID, error) { return current.User.Sid, nil }
	auditDBWindowsCurrentProcessRunsAsService = func(*windows.SID) (bool, error) { return false, nil }
	auditExportWindowsTokenOwner = func() (*windows.SID, error) {
		return windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	}
	t.Cleanup(func() {
		auditDBWindowsServiceAccountSID = previousSID
		auditDBWindowsCurrentProcessRunsAsService = previousRunsAs
		auditExportWindowsTokenOwner = previousOwner
	})
	system, err := auditExportWindowsTokenOwner()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := auditExportWindowsOwner(system)
	if err != nil {
		t.Fatal(err)
	}
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		t.Fatalf("managed SYSTEM export owner = %s, want BUILTIN\\Administrators", owner)
	}
	path := filepath.Join(t.TempDir(), "export-system.jsonl")
	file, err := CreateExportFileExclusive(path)
	if err != nil {
		t.Fatalf("SYSTEM export of a managed store: %v", err)
	}
	defer file.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := auditDBWindowsManagedRuntimeFileCanonical(sd, current.User.Sid)
	if err != nil || !canonical {
		t.Fatalf("managed SYSTEM export DACL canonical = %v, %v", canonical, err)
	}
}

func TestAuditExportOwnerKeepsNonSystemTokenOwner(t *testing.T) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		t.Fatalf("resolve current user SID: %v", err)
	}
	owner, err := auditExportWindowsOwner(current.User.Sid)
	if err != nil || !owner.Equals(current.User.Sid) {
		t.Fatalf("owner = %v, %v; want the token owner", owner, err)
	}
}
