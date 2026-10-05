// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"strings"
	"testing"
)

// The standalone Setup refuses before it stages anything when the volume is
// too full for the run, naming the volume, the free space and the space it
// needs (GAP-1070). An unknown free space never blocks Setup.
func TestEnterpriseSetupRefusesALowDiskBeforeStaging(t *testing.T) {
	original := enterpriseSetupFreeDiskBytes
	t.Cleanup(func() { enterpriseSetupFreeDiskBytes = original })
	payload := enterprisePayload{
		Manifest: enterprisePayloadManifest{DistributionFlavor: standaloneFlavor},
		Files: map[string]enterprisePayloadManifestFile{
			"defenseclaw.exe":         {Name: "defenseclaw.exe", Size: 100 << 20},
			"defenseclaw-gateway.exe": {Name: "defenseclaw-gateway.exe", Size: 200 << 20},
		},
	}
	if got, want := enterpriseSetupSpaceNeeded(payload, "ensure"), uint64(900<<20+enterpriseSetupDiskSpaceMargin); got != want {
		t.Fatalf("ensure needs %d, want %d", got, want)
	}
	if got, want := enterpriseSetupSpaceNeeded(payload, "status"), uint64(300<<20+enterpriseSetupDiskSpaceMargin); got != want {
		t.Fatalf("status needs %d, want %d", got, want)
	}
	dir := t.TempDir()
	enterpriseSetupFreeDiskBytes = func(string) (uint64, bool, error) { return 500 << 20, true, nil }
	err := requireEnterpriseSetupFreeSpace(dir, payload, "ensure")
	if err == nil || !strings.Contains(err.Error(), "500 MB free and about 1156 MB is needed") {
		t.Fatalf("low disk: %v", err)
	}
	if err := requireEnterpriseSetupFreeSpace(dir, payload, "status"); err == nil {
		t.Fatal("status staged on a volume without room for the payload")
	}
	enterpriseSetupFreeDiskBytes = func(string) (uint64, bool, error) { return 2 << 30, true, nil }
	if err := requireEnterpriseSetupFreeSpace(dir, payload, "ensure"); err != nil {
		t.Fatalf("enough space: %v", err)
	}
	enterpriseSetupFreeDiskBytes = func(string) (uint64, bool, error) { return 0, false, errors.New("unknown") }
	if err := requireEnterpriseSetupFreeSpace(dir, payload, "ensure"); err != nil {
		t.Fatalf("unknown free space blocked Setup: %v", err)
	}
}
