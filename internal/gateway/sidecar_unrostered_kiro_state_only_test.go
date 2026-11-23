// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10 GAP-1299 (F4 of the Kiro round 5 review): after an upgrade
// from a build whose teardown left its Kiro records, the first boot reclaims
// the unfinished teardown once. With no hook entry left anywhere it still
// said "removed the DefenseClaw hooks an earlier setup left" and wrote an
// audit row result=removed. It now says no hooks were left and that it
// finished the teardown, and the row says result=state-removed.
func TestBootReclaimOfOnlyAnUnfinishedKiroTeardownSaysNoHooksWereLeft(t *testing.T) {
	home := t.TempDir()
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed"}
	if err := connector.NewKiroConnector().Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// The user deleted every Kiro file; only the data folder still holds
	// what the setup wrote there (its records, hook script and token).
	kiro := filepath.Join(home, ".kiro")
	for _, path := range []string{
		filepath.Join(kiro, "hooks", "defenseclaw.json"),
		filepath.Join(kiro, "agents", "defenseclaw.json"),
		filepath.Join(kiro, "settings", "cli.json"),
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{DataDir: dataDir}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = "openclaw"
	s := &Sidecar{cfg: cfg, logger: logger}
	out := captureStderr(t, func() {
		s.reclaimUnguardedConnectorHooks(context.Background(), connector.NewDefaultRegistry())
	})
	if !strings.Contains(out, "connector kiro is not guarded: no DefenseClaw hooks were left") ||
		strings.Contains(out, "removed the DefenseClaw hooks") {
		t.Errorf("the boot reclaim of only an unfinished teardown said %q", out)
	}
	records, err := os.ReadDir(filepath.Join(dataDir, "connector_backups", "kiro"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, record := range records {
		t.Errorf("the boot reclaim kept the Kiro record %s", record.Name())
	}
	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Target != "kiro" {
			continue
		}
		if strings.Contains(e.Details, "result=removed") {
			t.Errorf("the audit row claims hooks were removed: %q", e.Details)
		}
		if strings.Contains(e.Details, "action=reclaim-unguarded result=state-removed") {
			found = true
		}
	}
	if !found {
		t.Errorf("no reclaim-unguarded result=state-removed audit row for kiro among %d events", len(events))
	}
}
