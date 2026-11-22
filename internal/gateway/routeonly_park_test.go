// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func withOSSRouteOnlyGate(t *testing.T) *connector.RouteOnlyGate {
	t.Helper()
	prev := ossRouteOnlyGate
	ossRouteOnlyGate = &connector.RouteOnlyGate{}
	t.Cleanup(func() { ossRouteOnlyGate = prev })
	return ossRouteOnlyGate
}

// rel-1-0-10:GAP-1133: an OSS gateway renders the real route-only config
// once it owns its API port and parks it again before it releases the port;
// each happens only on a change. Managed gateways never touch it.
func TestRouteOnlyPortOwnedRerendersOnChange(t *testing.T) {
	gate := withOSSRouteOnlyGate(t)
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly.Connectors = []string{"claudecode"}
	var renders, parks int32
	prevPark := routeOnlyPark
	routeOnlyPark = func(*config.Config) ([]string, error) { atomic.AddInt32(&parks, 1); return nil, nil }
	t.Cleanup(func() { routeOnlyPark = prevPark })
	a := &APIServer{scannerCfg: cfg, addr: "127.0.0.1:18970"}
	a.onRouteKeyRotated = func() { atomic.AddInt32(&renders, 1) }

	a.routeOnlyPortOwned(true)
	if !gate.Owned() || atomic.LoadInt32(&renders) != 1 {
		t.Fatalf("owning the port: owned=%v renders=%d", gate.Owned(), renders)
	}
	a.routeOnlyPortOwned(true)
	if atomic.LoadInt32(&renders) != 1 {
		t.Fatal("no change, no render")
	}
	a.routeOnlyPortOwned(false)
	if gate.Owned() || atomic.LoadInt32(&parks) != 1 || atomic.LoadInt32(&renders) != 1 {
		t.Fatalf("releasing the port: owned=%v parks=%d renders=%d", gate.Owned(), parks, renders)
	}

	managed := &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	managed.Enterprise.Profile = "standalone"
	managed.Routing = cfg.Routing
	a.scannerCfg = managed
	a.routeOnlyPortOwned(true)
	a.parkRouteOnly("test")
	if gate.Owned() || atomic.LoadInt32(&renders) != 1 || atomic.LoadInt32(&parks) != 1 {
		t.Fatal("a managed gateway renders through the guardian, not the OSS gate")
	}
}

// signingRouteOnlyConfig is an OSS route-only Claude Code on Bedrock with
// gateway signing from the AWS keys in the env vars ak and sk.
func signingRouteOnlyConfig(t *testing.T, dataDir, ak, sk string) *config.Config {
	t.Helper()
	cfg := &config.Config{DataDir: dataDir}
	cfg.Guardrail.Connector = "claudecode"
	cfg.Gateway.APIBind = "127.0.0.1"
	cfg.Gateway.APIPort = 18970
	cfg.Routing = config.RoutingConfig{Enabled: true, Classifier: config.RoutingClassifierRules, RouteOnly: config.RoutingRouteOnlyConfig{
		Connectors: []string{"claudecode"},
		Upstreams: map[string]config.RoutingUpstreamConfig{"claudecode": {
			BaseURL: "https://bedrock-runtime.us-east-1.amazonaws.com", API: config.RoutingAPIInvoke,
			Bedrock: &config.RoutingBedrockAuthConfig{Auth: "iam_credentials", AccessKeyEnv: ak, SecretKeyEnv: sk},
		}},
	}}
	return cfg
}

// rel-1-0-10:GAP-1133 round 2 (SQUATREV P2): the park on release must not
// depend on deriving the live route. With Bedrock gateway signing, a failing
// AWS credential fetch at stop time (expired SSO, an STS timeout) makes the
// live route nil; the old release re-rendered from it and so left the real
// route and X-DC-Route-Auth in place. The park is built from config alone.
func TestRouteOnlyReleaseParksWhenTheLiveRouteIsNil(t *testing.T) {
	isolateAWSEnv(t)
	settings := filepath.Join(t.TempDir(), "settings.json")
	prev := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settings
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = prev })
	gate := withOSSRouteOnlyGate(t)
	t.Setenv("DC_PARK_AK", "AKIDPARKTEST")
	t.Setenv("DC_PARK_SK", "park-secret")
	t.Setenv("DC_PARK_GONE_AK", "")
	t.Setenv("DC_PARK_GONE_SK", "")
	dataDir := t.TempDir()
	signing := signingRouteOnlyConfig(t, dataDir, "DC_PARK_AK", "DC_PARK_SK")

	a := &APIServer{scannerCfg: signing, addr: "127.0.0.1:18970"}
	a.onRouteKeyRotated = func() { (&Sidecar{}).rerenderRouteOnly(a.liveConfig()) }
	a.routeOnlyPortOwned(true)
	env := readClaudeEnv(t, settings)
	if env["ANTHROPIC_BEDROCK_BASE_URL"] != "http://127.0.0.1:18970/r/claudecode" || !strings.Contains(fmt.Sprint(env["ANTHROPIC_CUSTOM_HEADERS"]), connector.RouteOnlyHeader) {
		t.Fatalf("owned with signing working: env = %v", env)
	}

	// Stop time: the signing credential cannot be fetched now.
	failing := signingRouteOnlyConfig(t, dataDir, "DC_PARK_GONE_AK", "DC_PARK_GONE_SK")
	if routeOnlySetupFor(failing, "claudecode", apiListenAddr(failing)) != nil {
		t.Fatal("test setup: the live route should not be derivable with the credential fetch failing")
	}
	a.scannerCfg = failing
	a.routeOnlyPortOwned(false)
	if gate.Owned() {
		t.Fatal("released: gate still owned")
	}
	env = readClaudeEnv(t, settings)
	if got, _ := env["ANTHROPIC_BEDROCK_BASE_URL"].(string); !connector.IsParkedRouteBaseURL(got) {
		t.Fatalf("released with the signing credential failing: base url = %v, want parked", got)
	}
	if strings.Contains(fmt.Sprint(env["ANTHROPIC_CUSTOM_HEADERS"]), connector.RouteOnlyHeader) {
		t.Fatalf("released with the signing credential failing: the route credential stays: %v", env["ANTHROPIC_CUSTOM_HEADERS"])
	}
}

// rel-1-0-10:GAP-1133 round 2: every start parks before it binds, and the
// real route is rendered only once the port is ours. A render left by a
// crash is in place and another process holds the port at start: the OSS
// gateway parks it, and its Run ends on the held port with the render still
// parked. Once the port is free, the next start binds and renders the real
// route; its stop parks it again.
func TestRouteOnlyRunParksBeforeTheBindAndRendersOnceOwned(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "settings.json")
	prev := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settings
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = prev })
	gate := withOSSRouteOnlyGate(t)

	holder, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := holder.Addr().String()
	_, portText, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portText)
	restoreAPI, restoreBudget := inheritedAPIListener, apiListenRetryBudget
	t.Cleanup(func() { inheritedAPIListener, apiListenRetryBudget = restoreAPI, restoreBudget })
	inheritedAPIListener = func() (net.Listener, bool, error) { return nil, false, nil }
	apiListenRetryBudget = 50 * time.Millisecond

	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Gateway.APIBind = "127.0.0.1"
	cfg.Gateway.APIPort = port
	cfg.Routing = config.RoutingConfig{Enabled: true, Classifier: config.RoutingClassifierRules, RouteOnly: config.RoutingRouteOnlyConfig{
		Connectors: []string{"claudecode"},
		Upstreams:  map[string]config.RoutingUpstreamConfig{"claudecode": {BaseURL: "https://api.anthropic.com", API: config.RoutingAPIMessages}},
	}}
	live := "http://" + addr + "/r/claudecode"
	// Polled while the gateway rewrites the file: a read between the
	// replace steps sees no file, which is not a result.
	baseURL := func() string {
		raw, err := os.ReadFile(settings)
		if err != nil {
			return ""
		}
		var s struct {
			Env map[string]any `json:"env"`
		}
		if json.Unmarshal(raw, &s) != nil {
			return ""
		}
		got, _ := s.Env["ANTHROPIC_BASE_URL"].(string)
		return got
	}

	// The render a crashed gateway left behind.
	gate.SetOwned(true)
	applyRouteOnlyRender(connector.NewDefaultRegistry(), cfg, "claudecode", routeOnlySetupFor(cfg, "claudecode", addr))
	if got := baseURL(); got != live {
		t.Fatalf("crash leftover render = %v", got)
	}
	gate.SetOwned(false)

	start := func() (context.CancelFunc, chan error) {
		store, logger := testStoreAndV8Logger(t)
		api := NewAPIServer(addr, NewSidecarHealth(), nil, store, logger, cfg)
		api.SetConnectorRegistry(connector.NewDefaultRegistry())
		api.onRouteKeyRotated = func() { (&Sidecar{}).rerenderRouteOnly(api.liveConfig()) }
		ctx, cancel := context.WithCancel(context.Background())
		runErr := make(chan error, 1)
		go func() { runErr <- api.Run(ctx) }()
		return cancel, runErr
	}

	// Start with the port held: the OSS Run ends on the held port.
	cancel, runErr := start()
	select {
	case <-runErr:
	case <-time.After(15 * time.Second):
		t.Fatal("Run kept running with the port held")
	}
	cancel()
	if got := baseURL(); !connector.IsParkedRouteBaseURL(got) || gate.Owned() {
		t.Fatalf("start with the port held: render %q owned %v, want parked", got, gate.Owned())
	}
	if h := fmt.Sprint(readClaudeEnv(t, settings)["ANTHROPIC_CUSTOM_HEADERS"]); strings.Contains(h, connector.RouteOnlyHeader) {
		t.Fatalf("start with the port held: the route credential stays: %q", h)
	}

	// The port is free: the next start binds and renders the real route.
	_ = holder.Close()
	cancel, runErr = start()
	defer cancel()
	deadline := time.Now().Add(15 * time.Second)
	for baseURL() != live {
		select {
		case err := <-runErr:
			t.Fatalf("Run returned %v before rendering the route (render %q)", err, baseURL())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("port free: render = %q", baseURL())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if h := fmt.Sprint(readClaudeEnv(t, settings)["ANTHROPIC_CUSTOM_HEADERS"]); !strings.Contains(h, connector.RouteOnlyHeader) {
		t.Fatalf("owned: route credential missing: %q", h)
	}
	cancel()
	select {
	case <-runErr:
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not stop")
	}
	if got := baseURL(); !connector.IsParkedRouteBaseURL(got) {
		t.Fatalf("after the stop: render = %q, want parked", got)
	}
}

func readClaudeEnv(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]interface{}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	env, _ := s["env"].(map[string]interface{})
	return env
}

// Every OSS render the gateway writes goes through the gate (connector Setup
// options and the reload/rerender path); a restore stays nil.
func TestGatedRouteOnlyCarriesTheGate(t *testing.T) {
	gate := withOSSRouteOnlyGate(t)
	oss := &config.Config{DataDir: t.TempDir()}
	if gatedRouteOnly(oss, nil) != nil {
		t.Fatal("a restore stays nil")
	}
	route := &connector.RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/claudecode", Token: "t"}
	got := gatedRouteOnly(oss, route)
	if got.Gate != gate || route.Gate != nil || got.BaseURL != route.BaseURL || got.Token != route.Token {
		t.Fatalf("gated = %+v (input %+v)", got, route)
	}
	// A gateway that never moves the gate must not park its route for good.
	managed := &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	if got := gatedRouteOnly(managed, route); got != route || got.Gate != nil {
		t.Fatalf("managed gated = %+v", got)
	}
}

// rel-1-0-10:GAP-1133: an OSS Windows gateway accepts the route credential
// only from a process of its own account. The credential is sent on the
// wire, so a process of another account that held the port while the
// gateway was down has it; a replay from that account is refused and never
// reaches the upstream, and a peer that cannot be read is refused too.
func TestOSSWindowsRouteOnlyRefusesACapturedCredentialFromAnotherAccount(t *testing.T) {
	f := newRouteOnlyFixture(t)
	f.srv.goos = "windows"
	owner := f.srv.tokens.owner
	peerSID, peerErr := owner, error(nil)
	prev := routeOSSPeerSID
	routeOSSPeerSID = func(*http.Request) (string, error) { return peerSID, peerErr }
	t.Cleanup(func() { routeOSSPeerSID = prev })

	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil); rec.Code != http.StatusOK {
		t.Fatalf("this account = %d %s", rec.Code, rec.Body.String())
	}
	hits := atomic.LoadInt32(&f.origHits)
	peerSID = "S-1-5-21-9-9-9-1234"
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("another account replaying the captured credential = %d", rec.Code)
	}
	peerSID, peerErr = "", errors.New("open the client process: access is denied")
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unreadable peer = %d", rec.Code)
	}
	if atomic.LoadInt32(&f.origHits) != hits {
		t.Fatal("a refused route-only request reached the upstream")
	}
}
