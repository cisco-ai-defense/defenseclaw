//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// The managed gateway logs on as LocalSystem, so its token user is SYSTEM and
// the pinned service SID is a token group. The managed audit and judge-body
// DACLs must still be built and verified for it: the CI install lane failed
// with "managed gateway token SID S-1-5-18 does not match pinned service SID"
// and then "reopen existing database file for ACL hardening: Access is
// denied", and the gateway never started.
func TestAuditDBWindowsManagedDACLAcceptsLocalSystemGatewayToken(t *testing.T) {
	serviceSID, err := windows.StringToSid("S-1-5-80-555-444-333-222-111")
	if err != nil {
		t.Fatal(err)
	}
	const serviceName = "DefenseClawCertGateway_LocalSystem"
	t.Setenv(connector.WindowsGatewayServiceNameEnv, serviceName)
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\`+serviceName)
	previousSID := auditDBWindowsServiceAccountSID
	previousRuns := auditDBWindowsCurrentProcessRunsAsService
	previousOwner := auditDBWindowsCurrentProcessOwnerSID
	t.Cleanup(func() {
		auditDBWindowsServiceAccountSID = previousSID
		auditDBWindowsCurrentProcessRunsAsService = previousRuns
		auditDBWindowsCurrentProcessOwnerSID = previousOwner
	})
	auditDBWindowsServiceAccountSID = func(string) (*windows.SID, error) { return serviceSID, nil }
	runsAsGateway := true
	auditDBWindowsCurrentProcessRunsAsService = func(sid *windows.SID) (bool, error) {
		return runsAsGateway && sid.Equals(serviceSID), nil
	}
	auditDBWindowsCurrentProcessOwnerSID = func() (*windows.SID, error) { return serviceSID, nil }

	dacl, err := auditDBWindowsProtectedDACLForOwner(false, serviceSID)
	if err != nil {
		t.Fatalf("managed audit DACL for the LocalSystem gateway: %v", err)
	}
	canonical, err := auditDBWindowsManagedRuntimeFileCanonical(
		newAuditDBWindowsTestDescriptor(t, serviceSID, dacl), serviceSID,
	)
	if err != nil || !canonical {
		t.Fatalf("service-SID-owned audit descriptor canonical = %v, %v", canonical, err)
	}
	if !judgeBodyWindowsTrustedPrincipal(serviceSID) {
		t.Fatal("judge-body storage did not trust the gateway's own service SID")
	}

	// Any other LocalSystem process is still refused.
	runsAsGateway = false
	if _, err := auditDBWindowsProtectedDACLForOwner(false, serviceSID); err == nil ||
		!strings.Contains(err.Error(), "does not match pinned service SID") {
		t.Fatalf("a process without the gateway service SID built the managed DACL: %v", err)
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	auditDBWindowsCurrentProcessOwnerSID = func() (*windows.SID, error) { return localSystem, nil }
	if judgeBodyWindowsTrustedPrincipal(serviceSID) {
		t.Fatal("judge-body storage trusted a service SID that is not this process")
	}
}
