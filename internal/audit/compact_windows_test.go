// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package audit

import (
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// pinForeignGatewayService pins a managed gateway service whose SID is not
// this process's token (LocalService stands in for NT SERVICE\...): the
// test runs as an administrator who is not the gateway service.
func pinForeignGatewayService(t *testing.T) *windows.SID {
	t.Helper()
	service, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	const serviceName = "DefenseClawCertGateway_Compact"
	t.Setenv(connector.WindowsGatewayServiceNameEnv, serviceName)
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\`+serviceName)
	previous := auditDBWindowsServiceAccountSID
	auditDBWindowsServiceAccountSID = func(string) (*windows.SID, error) { return service, nil }
	t.Cleanup(func() { auditDBWindowsServiceAccountSID = previous })
	return service
}

func TestCompactStoreServiceOwnedAsAnAdministratorWithoutTheGatewayToken(t *testing.T) {
	path, rows := prunedStoreWithoutAutoVacuum(t)
	service := pinForeignGatewayService(t)
	setAuditDBWindowsInstallerRuntimeFileACL(t, path, service)

	// The store's custody open needs the gateway service's token
	// (review P1): an administrator's compaction cannot use it.
	if opened, err := openHardenedAuditSQLite(path, auditDBPathHooks{exclusive: true}); err == nil {
		_ = opened.Close()
		t.Fatal("the custody open of a managed store succeeded without the gateway token")
	}

	report, err := CompactStore(path, CompactOptions{ServiceOwned: true, FreeDiskBytes: roomyDisk})
	if err != nil {
		t.Fatalf("service-owned CompactStore: %v", err)
	}
	if report.Method != CompactVacuum || report.AutoVacuumAfter != "incremental" || report.ReclaimedBytes() <= 0 {
		t.Fatalf("report = %+v", report)
	}
	if got := compactRows(t, path); got != rows {
		t.Fatalf("rows after compaction = %d, want %d", got, rows)
	}
	// The store keeps the managed DACL: compact rewrote no ACL.
	if err := validateServiceOwnedAuditDB(path, false); err != nil {
		t.Fatalf("the store lost its managed DACL: %v", err)
	}
	assertNoSidecars(t, path, "the service-owned compaction")
	// A dry run and a second compaction create no -wal or -shm either, so
	// no administrator-owned sidecar with inherited entries is left for the
	// next run's checks to refuse (re-review P2-1).
	if _, err := CompactStore(path, CompactOptions{DryRun: true, ServiceOwned: true}); err != nil {
		t.Fatalf("service-owned dry run: %v", err)
	}
	assertNoSidecars(t, path, "the service-owned dry run")
	if again, err := CompactStore(path, CompactOptions{ServiceOwned: true, FreeDiskBytes: roomyDisk}); err != nil || again.Method != CompactNothing {
		t.Fatalf("second service-owned compaction = %+v, %v", again, err)
	}
	assertNoSidecars(t, path, "the second service-owned compaction")
}

func TestCompactStoreServiceOwnedRefusesAStoreWithoutTheManagedDACL(t *testing.T) {
	path, _ := prunedStoreWithoutAutoVacuum(t)
	pinForeignGatewayService(t)
	before, _ := compactFileSizes(path)
	if _, err := CompactStore(path, CompactOptions{ServiceOwned: true, FreeDiskBytes: roomyDisk}); err == nil {
		t.Fatal("a store without the managed service DACL was compacted as service-owned")
	}
	if size, _ := compactFileSizes(path); size != before {
		t.Fatalf("a refused compaction changed the store (size %d -> %d)", before, size)
	}
}
