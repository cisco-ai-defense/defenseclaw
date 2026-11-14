//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10 GAP-0568: a machine-policy connector that route-only routes on
// a standalone managed host gets per-user rows with the default
// unenrolled_users, so every enrolled account gets its own route render.
func TestEnumerateUnixRoutedMachinePolicyConnectorsGetRows(t *testing.T) {
	cfg := enumeratorConfig("claudecode", "codex", "cursor")
	registry := connector.NewDefaultRegistry()
	opts := UnixEnumerateOptions{Resolver: &fakeResolver{}, MachinePolicyConnectors: []string{"claudecode", "codex"}}
	_, report, err := EnumerateUnix(context.Background(), cfg, registry, opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(report.Connectors, ",") != "cursor" {
		t.Fatalf("not routed: machine-policy connectors get no rows: %v", report.Connectors)
	}
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"claudecode"}}
	_, report, _ = EnumerateUnix(context.Background(), cfg, registry, opts)
	if strings.Join(report.Connectors, ",") != "claudecode,cursor" {
		t.Fatalf("routed claudecode needs per-user rows: %v", report.Connectors)
	}
	cfg.Routing.Enabled = false
	_, report, _ = EnumerateUnix(context.Background(), cfg, registry, opts)
	if strings.Join(report.Connectors, ",") != "cursor" {
		t.Fatalf("routing off: no rows: %v", report.Connectors)
	}
	cfg.Routing.Enabled = true
	opts.OwnershipOffConnectors = []string{"claudecode"}
	_, report, _ = EnumerateUnix(context.Background(), cfg, registry, opts)
	if strings.Join(report.Connectors, ",") != "cursor" {
		t.Fatalf("ownership off keeps claudecode off every route: %v", report.Connectors)
	}
}

func TestMachinePolicyRouteOnlyNeedsAStandaloneManagedHost(t *testing.T) {
	cfg := enumeratorConfig("codex")
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"codex"}}
	if !MachinePolicyRouteOnly(cfg, "Codex") {
		t.Fatal("routed codex on a standalone managed host")
	}
	if MachinePolicyRouteOnly(cfg, "cursor") {
		t.Fatal("cursor is not route-only capable")
	}
	cfg.DeploymentMode, cfg.Enterprise.Profile = "", ""
	if MachinePolicyRouteOnly(cfg, "codex") || MachinePolicyRouteOnly(nil, "codex") {
		t.Fatal("OSS and nil configs render through Setup, not machine policy rows")
	}
}
