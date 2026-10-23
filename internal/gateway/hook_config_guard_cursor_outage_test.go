// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A managed administrator's explicit Cursor outage mode is re-rendered
// without a restart when the administrator changes it (r104 W3 G3-upg).
func TestHookConfigGuardRerendersManagedCursorOutageModeChange(t *testing.T) {
	root := t.TempDir()
	conn := &runtimePolicyCaptureConnector{
		stubConnector: stubConnector{name: "cursor"},
		configPath:    filepath.Join(root, "hooks.json"),
	}
	cached := connector.SetupOpts{DataDir: root, HookFailMode: "closed", GuardrailMode: "observe", ManagedEnterprise: true}
	if err := conn.Setup(context.Background(), cached); err != nil {
		t.Fatalf("initial Setup: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, time.Hour)
	if !guard.Start(ctx, conn, cached) {
		t.Fatal("hook registration guard did not start")
	}
	defer guard.Stop()
	sidecar := &Sidecar{}
	sidecar.bindHookRuntimePolicyResolver(guard)
	state := func() (int, connector.SetupOpts) {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		return conn.setupCalls, conn.lastOpts
	}

	live := config.DefaultConfig()
	live.DataDir = root
	live.DeploymentMode = managed.DeploymentModeManagedEnterprise
	live.Enterprise.Profile = managed.ProfileStandalone
	live.Guardrail.Mode = "observe"
	sidecar.publishConfig(live)
	before, _ := state()
	if err := guard.RefreshPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if calls, _ := state(); calls != before {
		t.Fatalf("unchanged outage mode re-rendered: Setup calls %d -> %d", before, calls)
	}

	open := cloneConfig(live)
	open.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"cursor": {HookFailMode: "open"}}
	if open.EffectiveHookFailModeForConnector("cursor") == live.EffectiveHookFailModeForConnector("cursor") {
		t.Fatal("precondition: the resolved Cursor mode changed")
	}
	sidecar.publishConfig(open)
	if err := guard.RefreshPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	calls, opts := state()
	if calls != before+1 || opts.ConfiguredHookFailMode != "open" || connector.OutageHookFailMode(opts, conn) != "open" {
		t.Fatalf("explicit open: Setup calls %d (want %d), configured %q", calls, before+1, opts.ConfiguredHookFailMode)
	}

	guard.mu.Lock()
	guard.suppressUntil = time.Time{}
	guard.mu.Unlock()
	sidecar.publishConfig(live)
	if err := guard.RefreshPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	calls, opts = state()
	if calls != before+2 || opts.ConfiguredHookFailMode != "" || connector.OutageHookFailMode(opts, conn) != "closed" {
		t.Fatalf("explicit open removed: Setup calls %d (want %d), configured %q", calls, before+2, opts.ConfiguredHookFailMode)
	}
}
