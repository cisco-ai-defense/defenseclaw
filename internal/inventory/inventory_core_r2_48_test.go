// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestEmptyIDEInventoryIsLatestSnapshot(t *testing.T) {
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	plugin := IDEPlugin{Fingerprint: "plugin-1", InstallID: "install-1", Product: "vscode", PluginID: "example.plugin", Enabled: "yes", LastSeen: now}
	for i, inv := range []*IDEInventory{
		{Installations: []IDEInstallation{{InstallID: "install-1", Family: "vscode", Product: "vscode", LastSeen: now}}, Plugins: []IDEPlugin{plugin}, persist: true},
		{persist: true},
	} {
		at := now.Add(time.Duration(i) * time.Minute)
		report := AIDiscoveryReport{Summary: AIDiscoverySummary{ScanID: []string{"before", "empty"}[i], ScannedAt: at}, IDEInventory: inv}
		if err := st.RecordScan(context.Background(), report, ConfidenceParams{}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.LatestIDEPlugins(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("latest plugins = %+v, %v", got, err)
	}
}
