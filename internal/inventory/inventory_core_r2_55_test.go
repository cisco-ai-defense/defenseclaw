// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"path/filepath"
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
	if len(inv.Plugins) != 1 || inv.Plugins[0].Fingerprint != prior.Fingerprint {
		t.Fatalf("published plugins = %+v, want the retained row (GAP-0594)", inv.Plugins)
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

func TestFailedIDEInventoryRecordRetriesOnNextFullScan(t *testing.T) {
	dir := t.TempDir()
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{Enabled: true, DataDir: dir}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	now := time.Now().UTC()
	plugin := IDEPlugin{Fingerprint: "one", InstallID: "install", Product: "vscode", PluginID: "example.plugin", Enabled: "yes"}
	makeInventory := func() *IDEInventory {
		return &IDEInventory{Plugins: []IDEPlugin{plugin}}
	}
	if err := svc.invStore.db.Close(); err != nil {
		t.Fatal(err)
	}
	first := svc.finishIDEInventory(makeInventory(), true, now)
	if !first.persist {
		t.Fatal("initial inventory did not request persistence")
	}
	svc.recordScanIfPossible(AIDiscoveryReport{Summary: AIDiscoverySummary{ScanID: "failed", ScannedAt: now}, IDEInventory: first})
	recovered, err := NewInventoryStore(filepath.Join(dir, "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	svc.invStore = recovered
	next := svc.finishIDEInventory(makeInventory(), true, now.Add(time.Minute))
	if !next.persist {
		t.Fatal("unchanged inventory did not retry after failed record")
	}
	svc.recordScanIfPossible(AIDiscoveryReport{Summary: AIDiscoverySummary{ScanID: "recovered", ScannedAt: now.Add(time.Minute)}, IDEInventory: next})
	got, err := recovered.LatestIDEPlugins(context.Background())
	if err != nil || len(got) != 1 || got[0].Fingerprint != plugin.Fingerprint {
		t.Fatalf("stored plugins = %+v, %v", got, err)
	}
}
