// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestNS7LaneUpgradeAndReload (GAP-0472, review round 7 check 3): a config from
// before guardrail.cascade.lanes.nonshell loads with the lane on, and a hot
// reload to a value the registry refuses keeps the last good config.
func TestNS7LaneUpgradeAndReload(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	path := filepath.Join(dir, config.DefaultConfigName)
	write := func(lane string) {
		raw := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  mode: observe\n"
		if lane != "" {
			raw += "  cascade:\n    lanes:\n      nonshell: " + lane + "\n"
		}
		raw += "observability: {}\n"
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mode := func(c *config.Config) string { return c.Guardrail.Cascade.Lanes.NonShellMode() }
	// An old config without the key loads, the lane on.
	write("")
	old, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatalf("old config without the key: %v", err)
	}
	if got := mode(old); got != "on" {
		t.Fatalf("old config: lane %q, want on", got)
	}
	if _, err := config.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile old config: %v", err)
	}
	// Start in Shadow, then hot-reload a bad value: refused, Shadow kept.
	write(" Shadow ")
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatalf("initial: %v", err)
	}
	applied := 0
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		applied++
		return nil
	})
	for _, bad := range []string{"enabled", "true", "''", "onn"} {
		write(bad)
		if err := mgr.Reload(context.Background(), "test"); err == nil {
			t.Errorf("%s: reload accepted", bad)
		}
		if got := mode(mgr.Current()); got != "shadow" {
			t.Errorf("%s: after a refused reload lane = %q, want shadow (last good)", bad, got)
		}
	}
	if applied != 0 {
		t.Errorf("apply ran %d times for refused configs", applied)
	}
	write("OFF")
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatalf("reload OFF: %v", err)
	}
	if got := mode(mgr.Current()); got != "off" {
		t.Errorf("after OFF reload lane = %q, want off", got)
	}
}
