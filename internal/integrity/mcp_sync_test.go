// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestSyncMCPServerBaselines_Drift(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	oc := filepath.Join(tmp, "openclaw.json")
	cfgJSON := `{"mcp":{"servers":{"demo":{"command":"node","args":["run.js"]}}}}`
	if err := os.WriteFile(oc, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmp, "audit.db")
	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	logger := audit.NewLogger(store)
	cfg := &config.Config{Claw: config.ClawConfig{ConfigFile: oc}}
	ic := &config.IntegrityConfig{
		Enabled:           true,
		MCP:               true,
		OnDrift:           "alert",
		DriftLogCooldownS: 1,
	}
	throttle := make(map[string]time.Time)

	if err := SyncMCPServerBaselines(cfg, store, logger, ic, throttle, nil); err != nil {
		t.Fatal(err)
	}
	b, err := store.GetIntegrityBaseline("mcp", "demo")
	if err != nil || b == nil {
		t.Fatalf("expected baseline: %v", err)
	}

	cfgJSON2 := `{"mcp":{"servers":{"demo":{"command":"node","args":["other.js"]}}}}`
	if err := os.WriteFile(oc, []byte(cfgJSON2), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := SyncMCPServerBaselines(cfg, store, logger, ic, throttle, nil); err != nil {
		t.Fatal(err)
	}

	alerts, err := store.ListAlerts(50)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range alerts {
		if e.Action == "integrity-drift" && strings.Contains(e.Target, "demo") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected integrity-drift alert after MCP config change")
	}
}
