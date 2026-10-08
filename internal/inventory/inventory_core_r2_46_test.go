// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMacOSPrivacySkipCarriesPreviousManifest(t *testing.T) {
	oldOS, oldFDA := discoveryGOOS, macOSFullDiskAccess
	t.Cleanup(func() { discoveryGOOS, macOSFullDiskAccess = oldOS, oldFDA })
	discoveryGOOS = "darwin"
	macOSFullDiskAccess = func() bool { return true }
	home := t.TempDir()
	mustWrite(t, filepath.Join(home, "Documents", "project", "package.json"), `{"dependencies":{"ai":"^3.0.0"}}`)
	mustWrite(t, filepath.Join(home, "work", "package.json"), `{"dependencies":{"ai":"^3.0.0"}}`)
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"),
		HomeDir: home, ScanRoots: []string{home}, IncludePackageManifests: true,
		MaxFilesPerScan: 100, MaxFileBytes: 1 << 20,
	}, catalog)
	cleanupPreparedDiscoveryService(t, svc)
	first, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sig := range first.Signals {
		if sig.Detector == "package_manifest" && sig.State == AIStateNew {
			found = true
		}
	}
	if !found {
		t.Fatal("first scan found no package manifest")
	}
	if err := os.Remove(filepath.Join(home, "work", "package.json")); err != nil {
		t.Fatal(err)
	}
	macOSFullDiskAccess = func() bool { return false }
	second, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatal(err)
	}
	if second.Summary.Result != "partial" || second.Summary.GoneSignals != 1 {
		t.Fatalf("privacy-skipped scan = %+v", second.Summary)
	}
}
