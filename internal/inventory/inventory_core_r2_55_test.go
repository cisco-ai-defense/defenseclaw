// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"testing"
	"time"
)

func TestPartialIDEInventoryRetainsBaselineWithoutRewrite(t *testing.T) {
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{Enabled: true, DataDir: t.TempDir()}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	now := time.Now().UTC()
	prior := IDEPlugin{Fingerprint: "kept", InstallID: "install", Product: "vscode", PluginID: "example.plugin", Enabled: "yes", LastSeen: now}
	svc.ideBaseline = map[string]IDEPlugin{prior.Fingerprint: prior}
	svc.ideRecordedAt = now
	makePartial := func() *IDEInventory {
		return &IDEInventory{Installations: []IDEInstallation{{InstallID: "install", Family: "vscode", Product: "vscode", Partial: true}}}
	}
	if inv := svc.finishIDEInventory(makePartial(), true, now.Add(time.Minute)); inv.persist {
		t.Fatal("unchanged partial inventory requested a rewrite")
	}
	svc.ideRecordedAt = now.Add(-13 * time.Hour)
	inv := svc.finishIDEInventory(makePartial(), true, now)
	if !inv.persist {
		t.Fatal("periodic refresh did not persist")
	}
	report := AIDiscoveryReport{Summary: AIDiscoverySummary{ScanID: "partial", ScannedAt: now}, IDEInventory: inv}
	if err := svc.InventoryStore().RecordScan(context.Background(), report, ConfidenceParams{}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.InventoryStore().LatestIDEPlugins(context.Background())
	if err != nil || len(got) != 1 || got[0].Fingerprint != prior.Fingerprint {
		t.Fatalf("retained plugins = %+v, %v", got, err)
	}
}
