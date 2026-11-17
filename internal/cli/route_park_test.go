// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10:GAP-1133 round 2: defenseclaw-gateway stop after it had to kill
// the gateway (Windows TerminateProcess, no graceful park), stop of a gateway
// that crashed, and start before anything else, park the route-only agent
// settings when no process of this account holds the API port; a foreground
// gateway of this account keeps its route.
func TestParkRouteOnlyWithoutGatewayParksOnlyAnUnownedPort(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "settings.json")
	prev := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settings
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = prev })
	unowned := true
	probes := 0
	prevProbe := routeOnlyPortUnowned
	routeOnlyPortUnowned = func(*config.Config) bool { probes++; return unowned }
	t.Cleanup(func() { routeOnlyPortUnowned = prevProbe })

	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Guardrail.Connector = "claudecode"
	cfg.Gateway.APIBind = "127.0.0.1"
	cfg.Gateway.APIPort = 18970
	cfg.Routing = config.RoutingConfig{Enabled: true, Classifier: config.RoutingClassifierRules, RouteOnly: config.RoutingRouteOnlyConfig{
		Connectors: []string{"claudecode"},
		Upstreams:  map[string]config.RoutingUpstreamConfig{"claudecode": {BaseURL: "https://api.anthropic.com", API: config.RoutingAPIMessages}},
	}}
	live := &connector.RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/claudecode", Token: "dcr1-left-by-a-kill"}
	render := func() {
		t.Helper()
		if err := connector.NewClaudeCodeConnector().ApplyRouteOnly(connector.SetupOpts{DataDir: cfg.DataDir}, live); err != nil {
			t.Fatal(err)
		}
	}
	read := func() (string, string) {
		t.Helper()
		raw, err := os.ReadFile(settings)
		if err != nil {
			t.Fatal(err)
		}
		var s struct {
			Env map[string]string `json:"env"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		return s.Env["ANTHROPIC_BASE_URL"], s.Env["ANTHROPIC_CUSTOM_HEADERS"]
	}

	render()
	parkRouteOnlyWithoutGateway(cfg, false)
	if base, headers := read(); !connector.IsParkedRouteBaseURL(base) || strings.Contains(headers, "dcr1-left-by-a-kill") {
		t.Fatalf("port unowned: base %q headers %q, want parked without the route credential", base, headers)
	}

	render()
	unowned = false
	parkRouteOnlyWithoutGateway(cfg, false)
	if base, _ := read(); base != live.BaseURL {
		t.Fatalf("this account holds the port: render = %q, want it kept", base)
	}

	probes = 0
	off := &config.Config{DataDir: t.TempDir()}
	parkRouteOnlyWithoutGateway(off, false)
	parkRouteOnlyWithoutGateway(nil, false)
	if probes != 0 {
		t.Fatal("no route-only connector: the port is not probed")
	}
}

// The ownership check reads the socket table only: with no listener it never
// opens a connection to the port (live, GAP-1133 round 2: a probe
// connection reached the other account's listener as an empty connection).
func TestRouteOnlyPortUnownedNeverConnects(t *testing.T) {
	prevAnswers := gatewayPortAnswers
	t.Cleanup(func() { gatewayPortAnswers = prevAnswers })
	gatewayPortAnswers = func(string) bool { t.Fatal("the park check connected to the API port"); return false }
	cfg := &config.Config{}
	cfg.Gateway.APIBind = "127.0.0.1"
	cfg.Gateway.APIPort = 18970
	cfg.DataDir = t.TempDir()
	if !routeOnlyPortUnowned(cfg) {
		t.Fatal("no listener: the port is unowned")
	}
}

// rel-1-0-10:GAP-1133 round 3: a park that cannot be written is not stderr
// only: stop returns it, so it exits non-zero with what to do.
func TestParkRouteOnlyWithoutGatewayReturnsAFailedPark(t *testing.T) {
	prevProbe, prevPark := routeOnlyPortUnowned, parkRouteOnlyAgents
	t.Cleanup(func() { routeOnlyPortUnowned, parkRouteOnlyAgents = prevProbe, prevPark })
	routeOnlyPortUnowned = func(*config.Config) bool { return true }
	parkRouteOnlyAgents = func(*config.Config) ([]string, error) {
		return nil, errors.New("claudecode: settings.json is not valid JSON")
	}
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly.Connectors = []string{"claudecode"}
	err := parkRouteOnlyWithoutGateway(cfg, false)
	if err == nil || !strings.Contains(err.Error(), "could not be parked") || !strings.Contains(err.Error(), "route-restore") {
		t.Fatalf("a failed park = %v, want an error naming the fix", err)
	}
	parkRouteOnlyAgents = func(*config.Config) ([]string, error) { return []string{"claudecode"}, nil }
	if err := parkRouteOnlyWithoutGateway(cfg, false); err != nil {
		t.Fatal(err)
	}
}
