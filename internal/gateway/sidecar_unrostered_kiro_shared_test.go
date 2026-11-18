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

// Review P2 of rel-1-0-10 GAP-1092: the files under ~/.kiro are shared by
// every DefenseClaw data folder of the account. Data folder B set Kiro up for
// a workspace, then install A set Kiro up and took over the global hook file,
// the defenseclaw agent and the default-agent setting. B's boot reclaim
// proved ownership by its workspace file and then tore down every Kiro file
// by name, so A's live global hooks went and A's Kiro ran unguarded. The
// reclaim removes only B's own entries: A's files stay byte for byte.
func TestBootReclaimLeavesAnotherInstallsSharedKiroFiles(t *testing.T) {
	home := t.TempDir()
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	dataA := filepath.Join(home, "a", ".defenseclaw")
	dataB := filepath.Join(home, "b", ".defenseclaw")
	workspace := filepath.Join(home, "work")
	for _, dir := range []string{dataA, dataB, workspace} {
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
	setup(dataB, workspace)
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
	if !strings.Contains(before[shared[0]], dataA) || strings.Contains(before[shared[0]], dataB) {
		t.Fatalf("the global hook file is not install A's alone:\n%s", before[shared[0]])
	}
	workspaceHooks := filepath.Join(workspace, ".kiro", "hooks", "defenseclaw.json")
	if data, err := os.ReadFile(workspaceHooks); err != nil || !strings.Contains(string(data), dataB) {
		t.Fatalf("the workspace hook file is not install B's: %v", err)
	}

	cfg := &config.Config{DataDir: dataB}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = "openclaw"
	cfg.Claw.WorkspaceDir = workspace
	s := &Sidecar{cfg: cfg}
	s.reclaimUnguardedConnectorHooks(context.Background(), connector.NewDefaultRegistry())

	for _, path := range shared {
		if got, err := os.ReadFile(path); err != nil || string(got) != before[path] {
			t.Errorf("install B's reclaim changed install A's %s (%v):\n%s", path, err, got)
		}
	}
	if data, err := os.ReadFile(workspaceHooks); err == nil && strings.Contains(string(data), dataB) {
		t.Errorf("install B's own workspace hooks stayed:\n%s", data)
	}
}
