// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const gap1133HomeGatewayEnv = "DC_GAP1133_HOME_GATEWAY_HELPER"

// TestGAP1133HomeGatewayHelper is the listener process of the test below:
// it stands in for this home's running gateway (another process).
func TestGAP1133HomeGatewayHelper(t *testing.T) {
	if os.Getenv(gap1133HomeGatewayEnv) == "" {
		t.Skip("helper process only")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("PORT %d\n", ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n') // until the parent closes stdin
}

// rel-1-0-10:GAP-1133 round 3 (SQUATREV2 P2): a second gateway process of
// the same home (a bare defenseclaw-gateway while the background gateway
// holds the port) must not park the working gateway's agents: neither its
// connector Setup write nor its pre-bind park. The working gateway here is a
// child process on the port that this home's private gateway-api.json names,
// as every gateway writes it once it binds.
func TestRouteOnlySecondSidecarKeepsTheWorkingGatewaysRoute(t *testing.T) {
	if os.Getenv(gap1133HomeGatewayEnv) != "" {
		t.Skip("helper process")
	}
	settings := filepath.Join(t.TempDir(), "settings.json")
	prev := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settings
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = prev })
	gate := withOSSRouteOnlyGate(t)

	helper := exec.Command(os.Args[0], "-test.run=^TestGAP1133HomeGatewayHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), gap1133HomeGatewayEnv+"=1")
	stdin, err := helper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = helper.Wait() })
	port := 0
	scan := bufio.NewScanner(stdout)
	for scan.Scan() {
		if v, ok := strings.CutPrefix(scan.Text(), "PORT "); ok {
			port, _ = strconv.Atoi(v)
			break
		}
	}
	if port == 0 {
		t.Fatal("the helper listener did not start")
	}
	go func() {
		for scan.Scan() {
		}
	}()

	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Gateway.APIBind = "127.0.0.1"
	cfg.Gateway.APIPort = port
	cfg.Routing = config.RoutingConfig{Enabled: true, Classifier: config.RoutingClassifierRules, RouteOnly: config.RoutingRouteOnlyConfig{
		Connectors: []string{"claudecode"},
		Upstreams:  map[string]config.RoutingUpstreamConfig{"claudecode": {BaseURL: "https://api.anthropic.com", API: config.RoutingAPIMessages}},
	}}
	record, _ := json.Marshal(map[string]any{"pid": helper.Process.Pid, "host": "127.0.0.1", "port": port})
	if err := configwrite.WriteFileDurablePublished(filepath.Join(cfg.DataDir, "gateway-api.json"), record, 0o600, safefile.ProtectFile); err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	live := "http://" + addr + "/r/claudecode"
	read := func() (string, string) {
		t.Helper()
		env := readClaudeEnv(t, settings)
		base, _ := env["ANTHROPIC_BASE_URL"].(string)
		return base, fmt.Sprint(env["ANTHROPIC_CUSTOM_HEADERS"])
	}

	// The working gateway's render.
	gate.SetOwned(true)
	applyRouteOnlyRender(connector.NewDefaultRegistry(), cfg, "claudecode", routeOnlySetupFor(cfg, "claudecode", addr))
	gate.SetOwned(false)
	if base, _ := read(); base != live {
		t.Fatalf("working gateway render = %q", base)
	}

	// The second process: its connector Setup write, then its Run (pre-bind
	// park, then the held port).
	applyRouteOnlyRender(connector.NewDefaultRegistry(), cfg, "claudecode", routeOnlySetupFor(cfg, "claudecode", addr))
	if base, headers := read(); base != live || !strings.Contains(headers, connector.RouteOnlyHeader) {
		t.Fatalf("second process Setup: base %q headers %q, want the working gateway's route kept", base, headers)
	}
	restoreAPI, restoreBudget := inheritedAPIListener, apiListenRetryBudget
	t.Cleanup(func() { inheritedAPIListener, apiListenRetryBudget = restoreAPI, restoreBudget })
	inheritedAPIListener = func() (net.Listener, bool, error) { return nil, false, nil }
	apiListenRetryBudget = 50 * time.Millisecond
	store, logger := testStoreAndV8Logger(t)
	api := NewAPIServer(addr, NewSidecarHealth(), nil, store, logger, cfg)
	api.SetConnectorRegistry(connector.NewDefaultRegistry())
	api.onRouteKeyRotated = func() { (&Sidecar{}).rerenderRouteOnly(api.liveConfig()) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- api.Run(ctx) }()
	select {
	case <-runErr:
	case <-time.After(15 * time.Second):
		t.Fatal("the second process kept running with the port held")
	}
	if base, headers := read(); base != live || !strings.Contains(headers, connector.RouteOnlyHeader) {
		t.Fatalf("second process Run: base %q headers %q, want the working gateway's route kept", base, headers)
	}

	// The working gateway is gone (no listener): the next park parks.
	_ = stdin.Close()
	_ = helper.Wait()
	if _, err := routeOnlyPark(cfg); err != nil {
		t.Fatal(err)
	}
	if base, _ := read(); !connector.IsParkedRouteBaseURL(base) {
		t.Fatalf("no gateway of this home holds the port: render %q, want parked", base)
	}
}
