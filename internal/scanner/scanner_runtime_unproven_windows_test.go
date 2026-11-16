// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// W2B-G-win review loop round 1: the gateway runs the scanner runtime only
// under an admission record that proves the production deployment admitted
// it. The schema 1 record DefenseClaw 1.0.3 wrote, which an --allow-unsigned
// certification install wrote alike for its unsigned scanner, is refused,
// also after the gateway ran the same bytes under a production record (the
// admission cache does not outlive the record).
func TestInstalledScannerRuntimeRefusesAnUnprovenAdmission(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	_, root := testenv.CiscoRuntimeTree(t, "DefenseClaw-ScannerRuntime")
	path := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	testenv.WriteAdminOnlyFile(t, path, []byte("unsigned certification scanner"))
	digest, err := managed.FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	oldRoot := scannerRuntimeRoot
	scannerRuntimeRoot = func() (string, error) { return root, nil }
	t.Cleanup(func() { scannerRuntimeRoot = oldRoot })
	legacy := []byte(`{"schema_version":1,"sha256":"` + digest + `","admitted_at":"2026-10-01T00:00:00Z"}`)
	record := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeAdmissionName)
	testenv.AsAdministratorsOwner(t, func() {
		if err := os.WriteFile(record, legacy, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if got, err := installedScannerRuntime(); got != "" || !errors.Is(err, managed.ErrScannerRuntimeAdmissionUnproven) {
		t.Fatalf("installedScannerRuntime() = %q, %v; want the unproven record refused", got, err)
	}
	testenv.AsAdministratorsOwner(t, func() {
		if err := managed.WriteScannerRuntimeAdmission(root, digest, managed.ScannerRuntimeTrustAuthenticode); err != nil {
			t.Fatal(err)
		}
	})
	if got, err := installedScannerRuntime(); err != nil || got != path {
		t.Fatalf("a production admission was refused: %q, %v", got, err)
	}
	testenv.AsAdministratorsOwner(t, func() {
		if err := os.WriteFile(record, legacy, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if got, err := installedScannerRuntime(); got != "" || err == nil {
		t.Fatalf("the cached admission outlived its record: %q, %v", got, err)
	}
	if scannerRuntimePath() != "" || scannerRuntimeProblem() == nil {
		t.Fatal("the scan would still run the scanner an unproven record names")
	}
}
