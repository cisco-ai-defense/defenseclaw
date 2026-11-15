//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
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

// Review r1 P2-1: routing a machine-policy connector must not drop the
// refusal of a user whose only installs are refused surfaces (inspect +
// unverified_versions: refuse), and that user gets no row (no render).
func TestEnumerateUnixRoutedMachinePolicyKeepsSurfaceRefusals(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	alice := makeHome(t, homes, "alice")
	opts := UnixEnumerateOptions{
		Resolver: &fakeResolver{
			accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}},
			listed:   []string{"alice"},
		},
		HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1, MachinePolicyConnectors: []string{"claudecode"},
		DiscoverSurfaces: func(context.Context, unixidentity.Account, []string) (UnixDiscovery, error) {
			return UnixDiscovery{Surfaces: map[string][]connector.AgentSurface{
				"claudecode": {{Surface: connector.HostSurfaceDesktop, Host: "claude-desktop", HostVersion: "0.0.1"}},
			}}, nil
		},
	}
	cfg := enumeratorConfig("claudecode")
	cfg.Enterprise.Enrollment.UnverifiedVersions = config.EnterpriseUnverifiedRefuse
	refused := func() (int, int) {
		manifest, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range report.RefusedSurfaces {
			if r.Connector == "claudecode" && r.User == "alice" {
				n++
			}
		}
		return n, len(manifest.Targets)
	}
	before, _ := refused()
	if before != 1 {
		t.Fatalf("fixture: not routed, the refused-surface user is recorded once, got %d", before)
	}
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"claudecode"}}
	after, rows := refused()
	if after != 1 || rows != 0 {
		t.Fatalf("routed: refused entries %d (want 1), rows %d (want 0)", after, rows)
	}
}
