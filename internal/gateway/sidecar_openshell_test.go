// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/gorilla/websocket"
)

func openShellReloadConfig(edit func(*config.Config)) *config.Config {
	cfg := &config.Config{}
	cfg.Gateway.APIPort = 18970
	cfg.OpenShell.Enabled = true
	if edit != nil {
		edit(cfg)
	}
	return cfg
}

// legacyStandaloneConfig is a host still configured for the removed
// openshell-sandbox 0.0.x standalone mode.
func legacyStandaloneConfig(edit func(*config.Config)) *config.Config {
	cfg := &config.Config{}
	cfg.OpenShell.Mode = "standalone"
	cfg.Guardrail.Host = "10.200.0.1"
	cfg.Gateway.APIPort = 18970
	if edit != nil {
		edit(cfg)
	}
	return cfg
}

// Every API listener, hook/plugin address, and health probe must agree on one
// address, or an upgrade health check on a legacy host dials 127.0.0.1 while
// the API listens on the veth host (or the reverse) and rolls back.
func TestAPIListenAddrUsesTheLegacyBindShim(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"legacy standalone", legacyStandaloneConfig(nil), "10.200.0.1:18970"},
		{"explicit api_bind", legacyStandaloneConfig(func(c *config.Config) { c.Gateway.APIBind = "127.0.0.1" }), "127.0.0.1:18970"},
		{"host mode", legacyStandaloneConfig(func(c *config.Config) { c.OpenShell.Mode = "" }), "127.0.0.1:18970"},
	} {
		if got := apiListenAddr(tc.cfg); got != tc.want {
			t.Errorf("%s listener = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Only the sandbox listeners (and leaving the legacy bind shim) are tied to
// the API server's lifecycle; every other openshell key is read per sandbox
// launch and must hot-reload.
func TestAPINeedsRestartForOpenShellListenersOnly(t *testing.T) {
	base := openShellReloadConfig(nil)
	disabled := func(c *config.Config) { c.OpenShell.Enabled = false }
	for _, tc := range []struct {
		name    string
		oldCfg  *config.Config
		newCfg  *config.Config
		restart bool
	}{
		{"enable", openShellReloadConfig(disabled), base, true},
		{"disable", base, openShellReloadConfig(disabled), true},
		{"ingress port", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.IngressPort = 19971 }), true},
		{"egress port", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.EgressPort = 19972 }), true},
		{"explicit port equal to derived", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.IngressPort = 18971 }), false},
		{"disabled port move", openShellReloadConfig(disabled),
			openShellReloadConfig(func(c *config.Config) { c.OpenShell.Enabled = false; c.OpenShell.EgressPort = 19972 }), false},
		{"profile", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.Profile = "strict" }), false},
		{"pack", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.Pack = "balanced" }), false},
		{"admin", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.Admin.MinProfile = "strict" }), false},
		{"egress lists", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.Egress.Block = []string{"paste.example"} }), false},
		{"harnesses", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.Harnesses = []string{"codex"} }), false},
		{"leave legacy standalone", legacyStandaloneConfig(nil), legacyStandaloneConfig(func(c *config.Config) { c.OpenShell.Mode = "" }), true},
		{"legacy-only sub-key", legacyStandaloneConfig(nil),
			legacyStandaloneConfig(func(c *config.Config) { c.OpenShell.SandboxHome = "/srv/sandbox" }), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := apiNeedsRestart(tc.oldCfg, tc.newCfg); got != tc.restart {
				t.Fatalf("apiNeedsRestart() = %v, want %v", got, tc.restart)
			}
		})
	}
}

// The openshell section hot-reloads, legacy keys included, except the flip
// out of legacy standalone mode.
func TestDiffConfigsTreatsOpenShellSectionAsHot(t *testing.T) {
	for _, tc := range []struct {
		name           string
		oldCfg, newCfg *config.Config
		restart        []string
	}{
		{"openshell 0.1 keys", openShellReloadConfig(nil), openShellReloadConfig(func(c *config.Config) {
			c.OpenShell.Enabled = false
			c.OpenShell.Profile = "balanced"
			c.OpenShell.Admin.AllowedHarnesses = []string{"codex"}
		}), nil},
		{"legacy sandbox_home", legacyStandaloneConfig(nil),
			legacyStandaloneConfig(func(c *config.Config) { c.OpenShell.SandboxHome = "/srv/sandbox" }), nil},
		{"legacy mode flip", legacyStandaloneConfig(nil),
			legacyStandaloneConfig(func(c *config.Config) { c.OpenShell.Mode = "" }), []string{"openshell.mode"}},
	} {
		diff := diffConfigs(tc.oldCfg, tc.newCfg)
		if tc.restart == nil && (!slices.Contains(diff.Changed, "openshell") || len(diff.RestartRequired) != 0) {
			t.Errorf("%s: changed=%v restart=%v, want a hot reload", tc.name, diff.Changed, diff.RestartRequired)
		}
		for _, key := range tc.restart {
			if !slices.Contains(diff.RestartRequired, key) {
				t.Errorf("%s: restart_required = %v, want %s", tc.name, diff.RestartRequired, key)
			}
		}
	}
}

func TestLegacySandboxHealthIsDegradedWithCleanupRemediation(t *testing.T) {
	s := &Sidecar{cfg: legacyStandaloneConfig(nil), health: NewSidecarHealth()}
	s.reportLegacySandboxHealth()
	sandbox := s.health.Snapshot().Sandbox
	if sandbox == nil || sandbox.State != StateDegraded || sandbox.LastError != legacySandboxHealthError ||
		sandbox.Details["api_bind"] != "10.200.0.1" || sandbox.Details["remediation"] != "defenseclaw sandbox legacy-cleanup" {
		t.Fatalf("legacy install sandbox health = %#v, want degraded with the cleanup remediation", sandbox)
	}
	host := &Sidecar{cfg: &config.Config{}, health: NewSidecarHealth()}
	host.reportLegacySandboxHealth()
	if got := host.health.Snapshot().Sandbox; got != nil {
		t.Fatalf("host-mode install reported a sandbox subsystem: %#v", got)
	}
}

// A custom provider edit must rebuild the judge that holds its endpoint.
func TestJudgeNeedsRebuildForProviderEdit(t *testing.T) {
	oldCfg := &config.Config{}
	newCfg := &config.Config{}
	oldCfg.LLMProviders.Custom = []config.LLMCustomProvider{{Name: "review", BaseURL: "https://old.example"}}
	newCfg.LLMProviders.Custom = []config.LLMCustomProvider{{Name: "review", BaseURL: "https://new.example"}}
	if !judgeNeedsRebuild(oldCfg, newCfg, false, nil, nil) {
		t.Fatal("custom provider endpoint edit left the judge bound to the old registry")
	}
}

// A CA rotation at the same path must replace the judge's captured TLS provider.
func TestJudgeNeedsRebuildForProviderCARotation(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	cfg := &config.Config{}
	cfg.LLMProviders.Custom = []config.LLMCustomProvider{{Name: "review", TLS: &config.LLMCustomProviderTLS{CACertFile: ca}}}
	if err := os.WriteFile(ca, []byte("old CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldProviders, err := buildGenerationProviders(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, []byte("new CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	newProviders, err := buildGenerationProviders(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if oldProviders.digest() == newProviders.digest() {
		t.Fatal("control: provider digest did not change")
	}
	if !judgeNeedsRebuild(cfg, cfg, false, oldProviders, newProviders) {
		t.Fatal("CA rotation reused the judge with its old TLS provider")
	}
}

// Removing OpenClaw closes the live WebSocket and stops reconnection.
func TestOpenClawConnectorHotDisableStopsFleetConnection(t *testing.T) {
	connected := make(chan struct{}, 2)
	closed := make(chan struct{}, 2)
	server := startMockGW(t, func(t *testing.T, conn *websocket.Conn) {
		connected <- struct{}{}
		rpcEchoLoop(t, conn)
		closed <- struct{}{}
	})
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	dataDir := testenv.PrivateTempDir(t)
	oldCfg := &config.Config{DataDir: dataDir}
	oldCfg.Gateway.Host = host
	oldCfg.Gateway.Port = port
	oldCfg.Gateway.FleetMode = "auto"
	oldCfg.Gateway.Token = "test-token"
	oldCfg.Gateway.DeviceKeyFile = filepath.Join(dataDir, "device.key")
	oldCfg.Guardrail.Connector = "codex"
	oldCfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {}, "openclaw": {}}
	withConfiguredOpenClaw(t, oldCfg)
	newCfg := cloneConfig(oldCfg)
	delete(newCfg.Guardrail.Connectors, "openclaw")
	if !gatewayShouldConnectForConfiguredConnector(oldCfg) || gatewayShouldConnectForConfiguredConnector(newCfg) {
		t.Fatal("control: removing OpenClaw did not disable the fleet predicate")
	}
	client, err := NewClient(&oldCfg.Gateway, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	s := &Sidecar{cfg: oldCfg, client: client, logger: audit.NewLogger(nil), health: NewSidecarHealth(), fleetReloadCh: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.runGatewayLoop(ctx) }()
	defer func() { cancel(); <-done; _ = client.Close() }()
	select {
	case <-connected:
	case <-time.After(2 * time.Second):
		t.Fatal("fleet WebSocket never connected")
	}
	deadline := time.After(2 * time.Second)
	for s.health.Snapshot().Gateway.State != StateRunning {
		select {
		case <-deadline:
			t.Fatal("fleet WebSocket never became ready")
		case <-time.After(time.Millisecond):
		}
	}
	s.publishConfig(newCfg)
	signalRestart(s.fleetReloadCh)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("fleet WebSocket stayed open after OpenClaw removal")
	}
	deadline = time.After(time.Second)
	for s.health.Snapshot().Gateway.State != StateDisabled {
		select {
		case <-deadline:
			t.Fatal("fleet loop did not park after OpenClaw removal")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case <-connected:
		t.Fatal("fleet loop reconnected after OpenClaw removal")
	case <-time.After(100 * time.Millisecond):
	}
	s.publishConfig(oldCfg)
	signalRestart(s.fleetReloadCh)
	select {
	case <-connected:
	case <-time.After(2 * time.Second):
		t.Fatal("fleet loop did not reconnect when OpenClaw was restored")
	}
	deadline = time.After(2 * time.Second)
	for s.health.Snapshot().Gateway.State != StateRunning {
		select {
		case <-deadline:
			t.Fatal("fleet loop did not become ready after OpenClaw was restored")
		case <-time.After(time.Millisecond):
		}
	}
}

// Enabling OpenClaw beside Codex must activate its routes and wake the fleet loop.
func TestOpenClawConnectorHotEnableActivatesAPIRoutesAndFleet(t *testing.T) {
	oldCfg := &config.Config{DataDir: t.TempDir()}
	oldCfg.Gateway.Host = "127.0.0.1"
	oldCfg.Guardrail.Connector = "codex"
	oldCfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {}}
	newCfg := cloneConfig(oldCfg)
	newCfg.Guardrail.Connectors["openclaw"] = config.PerConnectorGuardrailConfig{}
	if gatewayShouldConnectForConfiguredConnector(oldCfg) {
		t.Fatal("Codex-only loopback install unexpectedly connects to fleet")
	}
	if !gatewayShouldConnectForConfiguredConnector(newCfg) {
		t.Fatal("OpenClaw connector did not enable fleet uplink")
	}
	if !apiNeedsRestart(oldCfg, newCfg) {
		t.Fatal("API listener did not restart to register OpenClaw routes")
	}
	api := &APIServer{scannerCfg: newCfg}
	if !api.servesOpenClawRoutes() {
		t.Fatal("OpenClaw routes remained absent after connector enable")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	oldCfg.Gateway.Port = listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	oldCfg.Gateway.ReconnectMs = 100
	oldCfg.Gateway.MaxReconnectMs = 100
	newCfg.Gateway = oldCfg.Gateway
	s := &Sidecar{cfg: oldCfg, client: &Client{cfg: &oldCfg.Gateway}, health: NewSidecarHealth(), fleetReloadCh: make(chan struct{}, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.runGatewayLoop(ctx) }()
	deadline := time.After(500 * time.Millisecond)
	for s.health.Snapshot().Gateway.State != StateDisabled {
		select {
		case <-deadline:
			t.Fatal("fleet loop did not park before the config edit")
		case <-time.After(time.Millisecond):
		}
	}
	s.publishConfig(newCfg)
	signalRestart(s.fleetReloadCh)
	deadline = time.After(500 * time.Millisecond)
	for s.health.Snapshot().Gateway.State != StateReconnecting {
		select {
		case <-deadline:
			t.Fatal("fleet loop stayed disabled after enabling OpenClaw")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("fleet loop shutdown: %v", err)
	}
}
