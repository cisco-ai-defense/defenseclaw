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
