// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// routeWritingCaptureConnector is the hook connector double of the GAP-1664
// test: Setup records its options like runtimePolicyCaptureConnector and
// writes opts.RouteOnly into Claude Code settings.json with the real
// writer, as ClaudeCodeConnector.Setup does.
type routeWritingCaptureConnector struct {
	*runtimePolicyCaptureConnector
}

func (c routeWritingCaptureConnector) Setup(ctx context.Context, opts connector.SetupOpts) error {
	if err := c.runtimePolicyCaptureConnector.Setup(ctx, opts); err != nil {
		return err
	}
	return connector.NewClaudeCodeConnector().ApplyRouteOnly(opts, opts.RouteOnly)
}

// rel-1-0-10:GAP-1664: on dc-win2, with routing off in config.yaml, every
// guardrail use-pack wrote ANTHROPIC_BEDROCK_BASE_URL .../r/claudecode back
// into ~/.claude/settings.json, also right after routing disable --connector
// claudecode had restored it. The hook guard keeps the setup options it
// started with, route included, and a rule-pack switch re-renders the hooks
// through it (refreshHookGuardPolicies -> RefreshPolicy -> Setup). This is
// that sequence: the route a repair writes follows the published config.
func TestGAP1664PackSwitchDoesNotRerouteAnUnroutedConnector(t *testing.T) {
	gate := withOSSRouteOnlyGate(t)
	gate.SetOwned(true)
	root := t.TempDir()
	settings := filepath.Join(t.TempDir(), "settings.json")
	prevSettings := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settings
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = prevSettings })

	routed := config.DefaultConfig()
	routed.DataDir = root
	routed.Guardrail.Connector = "claudecode"
	routed.Guardrail.HookFailMode = "open"
	routed.Guardrail.RulePack = "default"
	routed.Gateway.APIBind = "127.0.0.1"
	routed.Gateway.APIPort = 19020
	routed.Routing = config.RoutingConfig{Enabled: true, Classifier: config.RoutingClassifierRules, RouteOnly: config.RoutingRouteOnlyConfig{
		Connectors: []string{"claudecode"},
		Upstreams: map[string]config.RoutingUpstreamConfig{"claudecode": {
			BaseURL: "https://bedrock-runtime.us-east-1.amazonaws.com", API: config.RoutingAPIInvoke,
		}},
	}}
	// routing disable --connector claudecode, then routing disable.
	off := cloneConfig(routed)
	off.Routing.Enabled = false
	off.Routing.RouteOnly = config.RoutingRouteOnlyConfig{}
	withPack := func(base *config.Config, pack string) *config.Config {
		next := cloneConfig(base)
		next.Guardrail.RulePack = pack
		return next
	}

	addr := apiListenAddr(routed)
	conn := routeWritingCaptureConnector{&runtimePolicyCaptureConnector{
		stubConnector: stubConnector{name: "claudecode"},
		configPath:    filepath.Join(root, "hooks.json"),
	}}
	// The options the gateway started the guard with (connectorSetupOptsChecked).
	opts := connector.SetupOpts{
		DataDir: root, HookFailMode: "open", PolicyTier: "default", APIAddr: addr,
		RouteOnly: gatedRouteOnly(routed, routeOnlySetupFor(routed, "claudecode", addr)),
	}
	if opts.RouteOnly == nil {
		t.Fatal("test setup: the routed config renders no route")
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, time.Hour)
	if !guard.Start(ctx, conn, opts) {
		t.Fatal("guard did not start")
	}
	defer guard.Stop()
	sidecar := &Sidecar{}
	sidecar.bindHookRuntimePolicyResolver(guard)
	sidecar.publishConfig(routed)

	refs := func() int {
		raw, err := os.ReadFile(settings)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Count(string(raw), "19020/r/claudecode")
	}
	restore := func() { // defenseclaw-gateway connector route-restore --connector claudecode
		if err := connector.NewClaudeCodeConnector().ApplyRouteOnly(connector.SetupOpts{DataDir: root}, nil); err != nil {
			t.Fatal(err)
		}
	}
	usePack := func(base *config.Config, pack string) {
		sidecar.publishConfig(withPack(base, pack))
		guard.mu.Lock()
		guard.suppressUntil = time.Time{}
		guard.mu.Unlock()
		if err := guard.RefreshPolicy(ctx); err != nil {
			t.Fatalf("use-pack %s: %v", pack, err)
		}
	}
	if got := refs(); got != 1 {
		t.Fatalf("routed: url refs = %d, want 1", got)
	}

	steps := []struct {
		name string
		do   func()
		want int
	}{
		{"routing off", func() { sidecar.publishConfig(off); restore() }, 0},
		{"use-pack strict", func() { usePack(off, "strict") }, 0},
		{"use-pack default", func() { usePack(off, "default") }, 0},
		{"routing disable --connector claudecode", restore, 0},
		{"use-pack strict again", func() { usePack(off, "strict") }, 0},
		// Routed again: a repair renders the current route.
		{"routing on, use-pack default", func() { usePack(routed, "default") }, 1},
	}
	for _, step := range steps {
		step.do()
		if got := refs(); got != step.want {
			raw, _ := os.ReadFile(settings)
			t.Fatalf("after %s: settings url refs = %d, want %d\n%s", step.name, got, step.want, raw)
		}
	}
}
