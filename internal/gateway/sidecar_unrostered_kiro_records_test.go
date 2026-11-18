// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

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

// Review round 4 P2 of rel-1-0-10 GAP-1092/GAP-1174: data folder B set Kiro
// up with workspace W1, claw.workspace_dir changed later (RHEL-U3-09), and
// install A took over the global hook file and the defenseclaw agent. Only
// B's backup record still names W1/.kiro/hooks/defenseclaw.json, so B's boot
// could not prove ownership and left its entries there for good. The boot
// reclaim reads the files B's records name: it removes B's entries from W1,
// leaves A's files byte for byte and drops B's Kiro records.
func TestBootReclaimCleansTheWorkspaceHookFileOnlyARecordNames(t *testing.T) {
	home := t.TempDir()
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	dataA := filepath.Join(home, "a", ".defenseclaw")
	dataB := filepath.Join(home, "b", ".defenseclaw")
	w1 := filepath.Join(home, "w1")
	w2 := filepath.Join(home, "w2")
	for _, dir := range []string{dataA, dataB, w1, w2} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	setup := func(dataDir, ws string) {
		t.Helper()
		opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed", WorkspaceDir: ws}
		if err := connector.NewKiroConnector().Setup(context.Background(), opts); err != nil {
			t.Fatalf("Setup %s: %v", dataDir, err)
		}
	}
	setup(dataB, w1)
	setup(dataA, "")
	kiro := filepath.Join(home, ".kiro")
	shared := []string{
		filepath.Join(kiro, "hooks", "defenseclaw.json"),
		filepath.Join(kiro, "agents", "defenseclaw.json"),
		filepath.Join(kiro, "settings", "cli.json"),
	}
	before := map[string]string{}
	for _, path := range shared {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = string(data)
	}
	w1Hooks := filepath.Join(w1, ".kiro", "hooks", "defenseclaw.json")
	if data, err := os.ReadFile(w1Hooks); err != nil || !strings.Contains(string(data), dataB) {
		t.Fatalf("the W1 hook file is not install B's: %v", err)
	}

	cfg := &config.Config{DataDir: dataB}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = "openclaw"
	cfg.Claw.WorkspaceDir = w2
	s := &Sidecar{cfg: cfg}
	s.reclaimUnguardedConnectorHooks(context.Background(), connector.NewDefaultRegistry())

	if data, err := os.ReadFile(w1Hooks); err == nil && strings.Contains(string(data), dataB) {
		t.Errorf("install B's hooks stayed in the workspace file only its record names:\n%s", data)
	}
	for _, path := range shared {
		if got, err := os.ReadFile(path); err != nil || string(got) != before[path] {
			t.Errorf("install B's reclaim changed install A's %s (%v):\n%s", path, err, got)
		}
	}
	records, err := os.ReadDir(filepath.Join(dataB, "connector_backups", "kiro"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, record := range records {
		t.Errorf("install B's reclaim kept the Kiro record %s", record.Name())
	}
}
