// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The standalone managed gateway's configured full-scan interval also governs
// its IDE inventory. The Secure Client fleet cadence remains unchanged.
func TestGAP0670ManagedStandaloneUsesConfiguredDiscoveryCadence(t *testing.T) {
	tests := []struct {
		name           string
		deploymentMode string
		profile        string
		full           time.Duration
		process        time.Duration
	}{
		{"standalone_default", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone, 5 * time.Minute, time.Minute},
		{"standalone_configured", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone, 11 * time.Minute, 2 * time.Minute},
		{"secure_client", managed.DeploymentModeManagedEnterprise, managed.ProfileSecureClient, 30 * time.Minute, 30 * time.Minute},
		{"oss", "", "", 5 * time.Minute, time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				DataDir:        t.TempDir(),
				DeploymentMode: tt.deploymentMode,
				Enterprise:     config.EnterpriseConfig{Profile: tt.profile},
				AIDiscovery: config.AIDiscoveryConfig{
					Enabled: true, ScanIntervalMin: 5, ProcessIntervalSec: 60,
				},
			}
			if tt.name == "standalone_configured" {
				cfg.AIDiscovery.ScanIntervalMin = 11
				cfg.AIDiscovery.ProcessIntervalSec = 120
			}
			opts := AIDiscoveryOptionsFromConfig(cfg)
			if opts.ScanInterval != tt.full || opts.ProcessInterval != tt.process {
				t.Fatalf("effective intervals = (%s, %s), want (%s, %s)",
					opts.ScanInterval, opts.ProcessInterval, tt.full, tt.process)
			}
		})
	}
}

// The shared full-scan path replaces the published inventory on a scheduled
// cycle, including its timestamp; a process-only cycle leaves it intact.
func TestGAP0670ScheduledFullScanPublishesNewIDEInventory(t *testing.T) {
	withoutMachineIDEs(t)
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	writeVSCodeExtensions(t, home, "example.first")
	previousOwners := discoveryHomeOwnersLookup
	discoveryHomeOwnersLookup = func(bool) []discoveryHomeOwner {
		return []discoveryHomeOwner{{Home: home, UserID: "1001", UserName: "alice"}}
	}
	t.Cleanup(func() { discoveryHomeOwnersLookup = previousOwners })
	stubProcessSnapshotSource(t, func() ([]processInfo, error) { return nil, nil })

	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, ManagedEnterprise: true, StandaloneEnterprise: true,
		DataDir: filepath.Join(root, "data"), HomeDir: home, HomeDirs: []string{home},
		ScanRoots: []string{filepath.Join(root, "empty")}, IDEInventory: config.IDEInventoryAll,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)

	if _, err := svc.runScan(context.Background(), true, "startup"); err != nil {
		t.Fatal(err)
	}
	first := svc.IDEInventory()
	if first == nil || len(first.Plugins) != 1 || first.Plugins[0].PluginID != "example.first" {
		t.Fatalf("startup inventory = %+v", first)
	}
	writeVSCodeExtensions(t, home, "example.first", "example.second")
	if _, err := svc.runScan(context.Background(), false, "process"); err != nil {
		t.Fatal(err)
	}
	if got := svc.IDEInventory(); got != first {
		t.Fatalf("process-only scan replaced the full inventory: %+v", got)
	}
	if _, err := svc.runScan(context.Background(), true, "scheduled"); err != nil {
		t.Fatal(err)
	}
	second := svc.IDEInventory()
	if second == nil || len(second.Plugins) != 2 || second.ScanID == first.ScanID ||
		!second.ScannedAt.After(first.ScannedAt) {
		t.Fatalf("scheduled inventory = %+v, want two plugins and a newer scan than %+v", second, first)
	}
}
