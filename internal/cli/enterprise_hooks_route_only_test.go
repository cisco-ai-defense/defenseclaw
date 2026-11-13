// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io"
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
	enterpriseHookRouteToken = func(_, connectorName, identity string) (string, error) {
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
	enterpriseHookRouteToken = func(_, connectorName, identity string) (string, error) {
		return "route-" + connectorName + "-" + identity, nil
	}
	enterpriseHookRouteOnlyGOOS = "linux"
	if r := enterpriseHookWindowsRouteOnly("codex", "CORP\\alice", alice, "127.0.0.1:18970"); r != nil {
		t.Fatalf("a non-Windows guardian path rendered %+v", r)
	}
	enterpriseHookRouteOnlyGOOS = "windows"
	for _, name := range []string{"claudecode", "codex"} {
		r := enterpriseHookWindowsRouteOnly(name, "CORP\\alice", alice, "127.0.0.1:18970")
		if r == nil || r.Token != "route-"+name+"-"+alice || r.BaseURL != "http://127.0.0.1:18970/r/"+name {
			t.Fatalf("%s render for an enrolled SID = %+v", name, r)
		}
	}
	for label, got := range map[string]*connector.RouteOnlySetup{
		"exempt by DOMAIN\\name (any case)": enterpriseHookWindowsRouteOnly("codex", "corp\\CAROL", carol, "127.0.0.1:18970"),
		"exempt by SID":                     enterpriseHookWindowsRouteOnly("codex", "CORP\\dave", "s-1-5-21-100-200-300-1004", "127.0.0.1:18970"),
		"not routed":                        enterpriseHookWindowsRouteOnly("cursor", "CORP\\alice", alice, "127.0.0.1:18970"),
		"exempt by bare name":               enterpriseHookWindowsRouteOnly("codex", "carol@corp.example", carol, "127.0.0.1:18970"),
	} {
		if got != nil {
			t.Fatalf("%s must not render: %+v", label, got)
		}
	}
}
