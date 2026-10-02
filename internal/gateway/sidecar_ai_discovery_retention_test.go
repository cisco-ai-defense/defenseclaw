// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// aiDiscoveryRetentionRaw renders a v8 config with AI discovery enabled.
// retentionDays < 0 leaves observability.local.retention_days unset.
func aiDiscoveryRetentionRaw(dataDir string, scanIntervalMin, retentionDays int) []byte {
	local := "observability: {}\n"
	if retentionDays >= 0 {
		local = fmt.Sprintf("observability:\n  local:\n    retention_days: %d\n", retentionDays)
	}
	return []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nai_discovery:\n  enabled: true\n  scan_interval_min: %d\n  scan_roots: [%q]\n%s",
		dataDir, scanIntervalMin, dataDir, local,
	))
}

// TestSidecarAIDiscoveryHistoryFollowsObservabilityRetention proves inventory
// scan history uses the committed observability.local.retention_days window:
// the default at bootstrap, an explicit value after a reload, and 0 on a
// replacement discovery service swapped in by the same reload.
func TestSidecarAIDiscoveryHistoryFollowsObservabilityRetention(t *testing.T) {
	// A resolvable token keeps the ai_discovery swap from synthesizing one.
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "retention-test-token")
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	initialRaw := aiDiscoveryRetentionRaw(fixture.dataDir, 5, -1)
	if err := os.WriteFile(fixture.configPath, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.publishConfig(initial)
	service, err := inventory.NewContinuousDiscoveryService(initial)
	if err != nil || service == nil {
		t.Fatalf("discovery service = %v, %v", service, err)
	}
	t.Cleanup(func() { _, _ = service.CloseIfNeverStarted() })
	service.SetHistoryRetentionDays(1) // bootstrap must replace this
	fixture.sidecar.aiDiscovery = service

	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, initialRaw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	if got := service.HistoryRetentionDays(); got != config.ObservabilityV8DefaultRetentionDays {
		t.Fatalf("bootstrap history retention = %d, want default %d", got, config.ObservabilityV8DefaultRetentionDays)
	}

	mgr := newConfigManagerWithSnapshot(
		fixture.configPath, initial, nil, nil,
		fixture.sidecar.observabilityV8ActivePlanDigest(),
		fixture.sidecar.applyConfigReloadSnapshot,
	)
	if err := os.WriteFile(fixture.configPath, aiDiscoveryRetentionRaw(fixture.dataDir, 5, 30), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(t.Context(), "test"); err != nil {
		t.Fatal(err)
	}
	if fixture.sidecar.aiDiscoverySnapshot() != service {
		t.Fatal("observability-only reload replaced the discovery service")
	}
	if got := service.HistoryRetentionDays(); got != 30 {
		t.Fatalf("reloaded history retention = %d, want 30", got)
	}

	// ai_discovery edits are restart-required through ConfigManager; drive the
	// apply boundary directly to cover its in-process service swap.
	nextRaw := aiDiscoveryRetentionRaw(fixture.dataDir, 10, 0)
	nextCfg, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, nextRaw)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := config.ParseCompileObservabilityV8(
		fixture.configPath, nextRaw,
		config.ObservabilityV8CompileOptions{DefaultDataDir: fixture.dataDir},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.sidecar.applyConfigReloadSnapshot(
		t.Context(), fixture.sidecar.currentConfig(), nextCfg,
		ConfigDiff{Changed: []string{"ai_discovery", "observability"}},
		configReloadSource{sourceName: fixture.configPath, raw: nextRaw, compiledV8: compiled},
	); err != nil {
		t.Fatal(err)
	}
	replacement := fixture.sidecar.aiDiscoverySnapshot()
	if replacement == nil || replacement == service {
		t.Fatal("ai_discovery reload did not swap in a replacement service")
	}
	t.Cleanup(func() { _, _ = replacement.CloseIfNeverStarted() })
	if got := replacement.HistoryRetentionDays(); got != 0 {
		t.Fatalf("replacement history retention = %d, want 0 (unbounded)", got)
	}
}
