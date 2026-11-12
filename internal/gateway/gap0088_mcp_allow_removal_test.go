// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// gap0088Gateway is a standalone managed Linux gateway with a real install
// watcher listing the servers its hooks report, on store.
type gap0088Gateway struct {
	h      *reportedMCPHarness
	w      *watcher.InstallWatcher
	cancel context.CancelFunc
	done   chan struct{}
}

func startGAP0088Gateway(t *testing.T, cfg *config.Config, store *audit.Store, logger *audit.Logger) *gap0088Gateway {
	t.Helper()
	h := &reportedMCPHarness{reported: &hookReportedMCPServers{}}
	h.api = &APIServer{scannerCfg: cfg, hookMCP: h.reported}
	w := watcher.New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(h.reported.list)
	w.SetMCPDiscoveryPoll(true)
	h.api.SetMCPAdmissionStatus(func(connector, server, home, cwd string) watcher.MCPAdmissionStatus {
		return w.MCPAdmissionStatus(watcher.MCPAdmissionQuery{Connector: connector, Server: server, Home: home, CWD: cwd})
	})
	ctx, cancel := context.WithCancel(context.Background())
	g := &gap0088Gateway{h: h, w: w, cancel: cancel, done: make(chan struct{})}
	go func() { defer close(g.done); _ = w.Run(ctx) }()
	t.Cleanup(g.stop)
	return g
}

func (g *gap0088Gateway) stop() {
	g.cancel()
	<-g.done
}

// settle calls the server in fresh sessions until the answer is want or the
// time is up, and returns the last answer.
func (g *gap0088Gateway) settle(t *testing.T, server assetfacts.MCPServer, want string) claudeCodeHookResponse {
	t.Helper()
	var resp claudeCodeHookResponse
	for i := 0; i < 100; i++ {
		resp = g.h.callInSession(t, "s-"+want+"-"+time.Now().Format("150405.000000"), server)
		if resp.Action == want {
			return resp
		}
		if i%10 == 9 {
			g.w.RequestRescan()
		}
		time.Sleep(50 * time.Millisecond)
	}
	return resp
}

func TestGAP0088ManagedGatewayRemovedAllowRuleBlocksTheAdmittedLoopbackServerAgain(t *testing.T) {
	t.Setenv("PATH", "")
	store, logger := testStoreAndLogger(t)
	dir := t.TempDir()
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy(), DeploymentMode: "managed_enterprise",
		Enterprise: config.EnterpriseConfig{Profile: "standalone"},
		DataDir:    dir, QuarantineDir: filepath.Join(dir, "quarantine"), PolicyDir: filepath.Join(dir, "policies")}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Gateway.Watcher.Enabled = true
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Watch.RescanEnabled = true
	cfg.Watch.RescanContentGated = true
	server := assetfacts.MCPServer{Name: "v2probe", URL: "http://127.0.0.1:19555/mcp", Transport: "http"}

	g := startGAP0088Gateway(t, cfg, store, logger)
	if resp := g.settle(t, server, "block"); resp.Action != "block" {
		t.Fatalf("before any allow: %q %q, want block", resp.Action, resp.SourceReason)
	}
	cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: server.Name, URL: server.URL}}
	if resp := g.settle(t, server, "allow"); resp.Action != "allow" {
		t.Fatalf("with the allow rule: %q %q, want allow", resp.Action, resp.SourceReason)
	}
	// Let the admission the allow queued run.
	time.Sleep(time.Second)
	g.settle(t, server, "allow")
	cfg.AssetPolicy.MCP.Allowed = nil
	if resp := g.settle(t, server, "block"); resp.Action != "block" {
		t.Fatalf("after the rule was removed: %q %q, want block", resp.Action, resp.SourceReason)
	}
	g.stop()
	// A gateway restart: a new watcher and an empty hook list on the same store.
	g = startGAP0088Gateway(t, cfg, store, logger)
	if resp := g.settle(t, server, "block"); resp.Action != "block" {
		t.Fatalf("after the restart: %q %q, want block", resp.Action, resp.SourceReason)
	}
	for i := 0; i < 5; i++ {
		resp := g.h.callInSession(t, "after-restart", server)
		if resp.Action != "block" {
			t.Fatalf("call %d after the restart: %q %q, want block", i, resp.Action, resp.SourceReason)
		}
		g.w.RequestRescan()
		time.Sleep(200 * time.Millisecond)
	}
}
