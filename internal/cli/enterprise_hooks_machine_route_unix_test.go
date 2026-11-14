//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10 GAP-0568: the worker writes a machine-policy connector's route
// render into the account's own agent file, verifies it, and takes it back.
func TestMachinePolicyRouteRenderVerifyRestore(t *testing.T) {
	registry := connector.NewDefaultRegistry()
	for _, tc := range []struct {
		name, file, marker string
	}{
		{"codex", filepath.Join(".codex", "config.toml"), "defenseclaw_route"},
		{"claudecode", filepath.Join(".claude", "settings.json"), connector.RouteOnlyHeader},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			route := &connector.RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/" + tc.name, Token: "dcr1-test-route-" + tc.name}
			opts := enterprisehooks.InstallOptions{ConnectorName: tc.name, UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid()}
			if err := verifyMachinePolicyRouteOnly(registry, withRoute(opts, route)); err == nil {
				t.Fatal("verify passes with no render")
			}
			if drift := applyMachinePolicyRouteOnly(registry, withRoute(opts, route)); drift != "" {
				t.Fatalf("render: %s", drift)
			}
			raw, err := os.ReadFile(filepath.Join(home, tc.file))
			if err != nil || !strings.Contains(string(raw), tc.marker) || !strings.Contains(string(raw), route.Token) || !strings.Contains(string(raw), "/r/"+tc.name) {
				t.Fatalf("render missing from the account file: %v %s", err, raw)
			}
			if err := verifyMachinePolicyRouteOnly(registry, withRoute(opts, route)); err != nil {
				t.Fatalf("verify after render: %v", err)
			}
			rotated := *route
			rotated.Token = "dcr1-test-route-rotated"
			if err := verifyMachinePolicyRouteOnly(registry, withRoute(opts, &rotated)); err == nil || !strings.Contains(err.Error(), "route_config_drift") {
				t.Fatalf("a stale credential is not drift: %v", err)
			}
			if drift := applyMachinePolicyRouteOnly(registry, withRoute(opts, nil)); drift != "" {
				t.Fatalf("restore: %s", drift)
			}
			raw, _ = os.ReadFile(filepath.Join(home, tc.file))
			if strings.Contains(string(raw), route.Token) || strings.Contains(string(raw), "/r/"+tc.name) {
				t.Fatalf("restore left the render: %s", raw)
			}
			if err := verifyMachinePolicyRouteOnly(registry, withRoute(opts, nil)); err != nil {
				t.Fatalf("verify after restore with routing off: %v", err)
			}
		})
	}
}

func TestMachinePolicyRouteRestoreTouchesNothingUnrendered(t *testing.T) {
	home := t.TempDir()
	opts := enterprisehooks.InstallOptions{ConnectorName: "claudecode", UserHome: home}
	if drift := applyMachinePolicyRouteOnly(connector.NewDefaultRegistry(), opts); drift != "" {
		t.Fatalf("restore with nothing rendered: %s", drift)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude")); !os.IsNotExist(err) {
		t.Fatalf("a restore with nothing rendered created the agent folder: %v", err)
	}
}

func withRoute(opts enterprisehooks.InstallOptions, route *connector.RouteOnlySetup) enterprisehooks.InstallOptions {
	opts.RouteOnly = route
	return opts
}
