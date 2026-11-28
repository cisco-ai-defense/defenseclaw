// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The guardian renders route-only only for routed connectors of enrolled
// users, never for root or exempt accounts, and with that user credential.
func TestEnterpriseHookRouteOnlyRendersEnrolledUsersOnly(t *testing.T) {
	prevCfg, prevToken, prevLog := cfg, enterpriseHookRouteToken, enterpriseHookRouteOnlyLog
	t.Cleanup(func() { cfg, enterpriseHookRouteToken, enterpriseHookRouteOnlyLog = prevCfg, prevToken, prevLog })
	enterpriseHookRouteOnlyLog = io.Discard
	cfg = &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Enterprise.Enrollment.ExemptUsers = []string{"carol", "1004"}
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"codex"}, Upstreams: map[string]config.RoutingUpstreamConfig{"codex": {BaseURL: "https://api.openai.com/v1", API: "responses"}}}
	tokenErr := error(nil)
	enterpriseHookRouteToken = func(_, connectorName, identity string, _ bool) (string, error) {
		return "route-" + connectorName + "-" + identity, tokenErr
	}
	route := enterpriseHookRouteOnly("codex", "alice", "1001", "127.0.0.1:18970")
	if route == nil || route.Token != "route-codex-1001" || route.BaseURL != "http://127.0.0.1:18970/r/codex" {
		t.Fatalf("enrolled user render = %+v", route)
	}
	for name, got := range map[string]*connector.RouteOnlySetup{
		"connector not routed": enterpriseHookRouteOnly("claudecode", "alice", "1001", "127.0.0.1:18970"),
		"root":                 enterpriseHookRouteOnly("codex", "root", "0", "127.0.0.1:18970"),
		"exempt by name":       enterpriseHookRouteOnly("codex", "carol", "1003", "127.0.0.1:18970"),
		"exempt by uid":        enterpriseHookRouteOnly("codex", "dave", "1004", "127.0.0.1:18970"),
		"not an identity":      enterpriseHookRouteOnly("codex", "alice", "alice", "127.0.0.1:18970"),
	} {
		if got != nil {
			t.Fatalf("%s must not render: %+v", name, got)
		}
	}
	tokenErr = errors.New("no epoch yet")
	if r := enterpriseHookRouteOnly("codex", "alice", "1001", "127.0.0.1:18970"); r != nil {
		t.Fatal("no credential means no render")
	}
	tokenErr = nil
	cfg.DeploymentMode, cfg.Enterprise.Profile = "", ""
	if r := enterpriseHookRouteOnly("codex", "alice", "1001", "127.0.0.1:18970"); r != nil {
		t.Fatal("OSS installs render through Setup, not the guardian")
	}
}

// The Windows guardian paths (install, verify, reconcile) render route-only
// per enrolled SID only on Windows; Linux and macOS share those paths with
// the Secure Client profile and get nothing from them.
func TestEnterpriseHookWindowsRouteOnlyRendersPerSID(t *testing.T) {
	prevCfg, prevToken, prevLog, prevGOOS := cfg, enterpriseHookRouteToken, enterpriseHookRouteOnlyLog, enterpriseHookRouteOnlyGOOS
	t.Cleanup(func() {
		cfg, enterpriseHookRouteToken, enterpriseHookRouteOnlyLog, enterpriseHookRouteOnlyGOOS = prevCfg, prevToken, prevLog, prevGOOS
	})
	enterpriseHookRouteOnlyLog = io.Discard
	const alice, carol = "S-1-5-21-100-200-300-1001", "S-1-5-21-100-200-300-1003"
	cfg = &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Enterprise.Enrollment.ExemptUsers = []string{"CORP\\carol", "S-1-5-21-100-200-300-1004"}
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"claudecode", "codex"}, Upstreams: map[string]config.RoutingUpstreamConfig{
		"claudecode": {BaseURL: "https://api.anthropic.com", API: "messages"},
		"codex":      {BaseURL: "https://api.openai.com/v1", API: "responses"},
	}}
	enterpriseHookRouteToken = func(_, connectorName, identity string, _ bool) (string, error) {
		return "route-" + connectorName + "-" + identity, nil
	}
	enterpriseHookRouteOnlyGOOS = "linux"
	if r := enterpriseHookWindowsRouteOnly("codex", "CORP\\alice", alice, "127.0.0.1:18970", true); r != nil {
		t.Fatalf("a non-Windows guardian path rendered %+v", r)
	}
	enterpriseHookRouteOnlyGOOS = "windows"
	for _, name := range []string{"claudecode", "codex"} {
		r := enterpriseHookWindowsRouteOnly(name, "CORP\\alice", alice, "127.0.0.1:18970", true)
		if r == nil || r.Token != "route-"+name+"-"+alice || r.BaseURL != "http://127.0.0.1:18970/r/"+name {
			t.Fatalf("%s render for an enrolled SID = %+v", name, r)
		}
	}
	for label, got := range map[string]*connector.RouteOnlySetup{
		"exempt by DOMAIN\\name (any case)": enterpriseHookWindowsRouteOnly("codex", "corp\\CAROL", carol, "127.0.0.1:18970", true),
		"exempt by SID":                     enterpriseHookWindowsRouteOnly("codex", "CORP\\dave", "s-1-5-21-100-200-300-1004", "127.0.0.1:18970", true),
		"not routed":                        enterpriseHookWindowsRouteOnly("cursor", "CORP\\alice", alice, "127.0.0.1:18970", true),
		"exempt by bare name":               enterpriseHookWindowsRouteOnly("codex", "carol@corp.example", carol, "127.0.0.1:18970", true),
	} {
		if got != nil {
			t.Fatalf("%s must not render: %+v", label, got)
		}
	}
}

// A managed host whose only routed connectors are claudecode and codex has
// no hook-native target that mints the per-user credential key, so the route
// render must mint it; verify only loads it (rel-1-0-10:GAP-0763). On
// Windows the key custody is the protected DACL the gateway service reads,
// the identity is a SID and the credential also binds the route epoch the
// gateway publishes (rel-1-0-10:GAP-1514).
func TestEnterpriseHookRouteOnlyRenderMintsTheMissingKeyAndVerifyDoesNot(t *testing.T) {
	prevCfg, prevLog := cfg, enterpriseHookRouteOnlyLog
	t.Cleanup(func() { cfg, enterpriseHookRouteOnlyLog = prevCfg, prevLog })
	var log strings.Builder
	enterpriseHookRouteOnlyLog = &log
	dataDir := enterpriseHookTokenTestDataDir(t)
	user, _ := enterpriseHookTestUserIdentities()
	epoch := publishEnterpriseHookTestRouteEpoch(t, dataDir)
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"claudecode", "codex"}, Upstreams: map[string]config.RoutingUpstreamConfig{
		"claudecode": {BaseURL: "https://api.anthropic.com", API: "messages"},
		"codex":      {BaseURL: "https://api.openai.com/v1", API: "responses"},
	}}

	// Verify expects the route and reports why it cannot be derived
	// (route_config_drift with the cause, rel-1-0-10:GAP-0800).
	if r := enterpriseHookVerifyRouteOnly("codex", "alice", user, "127.0.0.1:18970"); r == nil || r.Token != "" || !strings.Contains(r.Unavailable, "per-user credential key is missing") {
		t.Fatalf("verify without a key = %+v", r)
	}
	if !strings.Contains(log.String(), "per-user credential key is missing") {
		t.Fatalf("verify without a key logged %q", log.String())
	}
	if key, err := connector.LoadUserScopedTokenKey(dataDir); err != nil || key != "" {
		t.Fatalf("verify minted a key: %q %v", key, err)
	}

	rendered := enterpriseHookRouteOnly("codex", "alice", user, "127.0.0.1:18970")
	if rendered == nil || rendered.Token == "" || rendered.BaseURL != "http://127.0.0.1:18970/r/codex" {
		t.Fatalf("render on a host without a key = %+v (log %q)", rendered, log.String())
	}
	key, err := connector.LoadUserScopedTokenKey(dataDir)
	if err != nil || key == "" {
		t.Fatalf("render did not mint the key: %v", err)
	}
	keyPath, err := connector.UserScopedTokenKeyPath(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	assertEnterpriseHookSecretCustody(t, dataDir, keyPath, "per-user credential key")
	want, err := connector.ManagedRouteToken(key, epoch, "codex", user)
	if err != nil || rendered.Token != want {
		t.Fatalf("rendered route credential is not the one the gateway derives: %v", err)
	}
	verified := enterpriseHookVerifyRouteOnly("codex", "alice", user, "127.0.0.1:18970")
	if verified == nil || verified.Token != rendered.Token {
		t.Fatal("verify after the render does not expect the rendered credential")
	}
	if claude := enterpriseHookRouteOnly("claudecode", "alice", user, "127.0.0.1:18970"); claude == nil || claude.Token == rendered.Token {
		t.Fatalf("claudecode render = %+v", claude)
	}
}

// rel-1-0-10:GAP-0800: a routed connector whose route credential cannot be
// derived is drift on verify (the guardian repairs it, status says why);
// the render paths still write nothing and keep the hooks.
func TestEnterpriseHookVerifyRouteOnlyReportsAnUnderivableRouteAsDrift(t *testing.T) {
	prevCfg, prevToken, prevLog := cfg, enterpriseHookRouteToken, enterpriseHookRouteOnlyLog
	t.Cleanup(func() { cfg, enterpriseHookRouteToken, enterpriseHookRouteOnlyLog = prevCfg, prevToken, prevLog })
	enterpriseHookRouteOnlyLog = io.Discard
	cfg = &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"claudecode"}, Upstreams: map[string]config.RoutingUpstreamConfig{"claudecode": {BaseURL: "https://api.anthropic.com", API: "messages"}}}
	enterpriseHookRouteToken = func(string, string, string, bool) (string, error) {
		return "", errors.New("the gateway has not published its route epoch yet")
	}
	if r := enterpriseHookRouteOnly("claudecode", "alice", "1001", "127.0.0.1:18970"); r != nil {
		t.Fatalf("a render without a credential wrote %+v", r)
	}
	expected := enterpriseHookVerifyRouteOnly("claudecode", "alice", "1001", "127.0.0.1:18970")
	if expected == nil || expected.Unavailable == "" {
		t.Fatalf("verify = %+v", expected)
	}
	err := connector.RouteOnlyDrift(connector.NewClaudeCodeConnector(), connector.SetupOpts{DataDir: cfg.DataDir}, expected)
	if !errors.Is(err, connector.ErrRouteConfigDrift) || !strings.Contains(err.Error(), "route epoch") {
		t.Fatalf("drift = %v", err)
	}
	// Not routed, root and exempt accounts still expect nothing.
	if r := enterpriseHookVerifyRouteOnly("codex", "alice", "1001", "127.0.0.1:18970"); r != nil {
		t.Fatalf("an unrouted connector expects %+v", r)
	}
	if r := enterpriseHookVerifyRouteOnly("claudecode", "root", "0", "127.0.0.1:18970"); r != nil {
		t.Fatalf("root expects %+v", r)
	}
}
