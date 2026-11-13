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
