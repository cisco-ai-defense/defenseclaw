//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// TestWindowsRouteOnlyRenderDriftRestore: the managed Windows guardian
// renders route-only into the target profile own agent files (Claude Code
// %USERPROFILE%\.claude\settings.json, Codex %USERPROFILE%\.codex\config.toml)
// with the custody placeholder, keeps its record in the per-user data dir,
// reports drift on an edit and on a left-over render, and restores the
// user values as the target (S1 DESIGN 21).
func TestWindowsRouteOnlyRenderDriftRestore(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, "AppData", "Local", "DefenseClaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	machineWide := filepath.Join(t.TempDir(), "managed-settings.json")
	previousImpersonation := windowsEnterpriseTargetImpersonation
	impersonated := 0
	windowsEnterpriseTargetImpersonation = func(_ *windows.SID, gotHome string, fn func() error) error {
		if gotHome != home {
			t.Errorf("impersonated for home %s", gotHome)
		}
		impersonated++
		return fn()
	}
	t.Cleanup(func() { windowsEnterpriseTargetImpersonation = previousImpersonation })
	registry := newWindowsEnterpriseConnectorRegistry()
	sid, err := windows.StringToSid("S-1-5-21-100-200-300-1001")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		file string
		seed string
	}{
		{"claudecode", filepath.Join(home, ".claude", "settings.json"), "{\n  \"env\": {\n    \"ANTHROPIC_API_KEY\": \"sk-ant-user-own\"\n  }\n}"},
		{"codex", filepath.Join(home, ".codex", "config.toml"), "model = \"gpt-5\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, ok := registry.Get(tc.name)
			if !ok {
				t.Fatalf("no %s connector", tc.name)
			}
			if err := os.MkdirAll(filepath.Dir(tc.file), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tc.file, []byte(tc.seed), 0o600); err != nil {
				t.Fatal(err)
			}
			route := &connector.RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/" + tc.name, Token: "dcr1-" + tc.name, Custody: true}
			if err := verifyWindowsRouteOnly(conn, home, dataDir, nil); err != nil {
				t.Fatalf("no render yet and none wanted: %v", err)
			}
			if err := verifyWindowsRouteOnly(conn, home, dataDir, route); !errors.Is(err, connector.ErrRouteConfigDrift) {
				t.Fatalf("a missing render must be drift, got %v", err)
			}
			if err := connector.WithUserHomeDir(home, func() error { return applyWindowsRouteOnly(conn, dataDir, route) }); err != nil {
				t.Fatal(err)
			}
			raw, _ := os.ReadFile(tc.file)
			if !strings.Contains(string(raw), "/r/"+tc.name) || !strings.Contains(string(raw), route.Token) {
				t.Fatalf("render missing in %s:\n%s", tc.file, raw)
			}
			if strings.Contains(string(raw), "sk-ant-user-own") {
				t.Fatal("a custody render keeps the user key")
			}
			if err := verifyWindowsRouteOnly(conn, home, dataDir, route); err != nil {
				t.Fatalf("fresh render drift = %v", err)
			}
			rotated := &connector.RouteOnlySetup{BaseURL: route.BaseURL, Token: "dcr1-rotated", Custody: true}
			if err := verifyWindowsRouteOnly(conn, home, dataDir, rotated); !errors.Is(err, connector.ErrRouteConfigDrift) {
				t.Fatalf("a rotated credential must be drift, got %v", err)
			}
			if err := verifyWindowsRouteOnly(conn, home, dataDir, nil); !errors.Is(err, connector.ErrRouteConfigDrift) {
				t.Fatalf("a left-over render must be drift, got %v", err)
			}
			if err := restoreWindowsRouteOnlyAsTarget(conn, sid, home, dataDir); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(tc.file)
			if strings.Contains(string(after), "/r/"+tc.name) || strings.Contains(string(after), route.Token) {
				t.Fatalf("restore left the render:\n%s", after)
			}
			if err := verifyWindowsRouteOnly(conn, home, dataDir, nil); err != nil {
				t.Fatalf("after restore = %v", err)
			}
			if _, err := os.Stat(machineWide); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a machine-wide file was written")
			}
		})
	}
	if impersonated != len(cases) {
		t.Fatalf("restore impersonated %d times; want once per connector", impersonated)
	}
}

// TestRemoveWindowsRouteOnlyOnUnenrollIsBestEffort: a removal without a
// profile, or of another connector, touches nothing and never fails.
func TestRemoveWindowsRouteOnlyOnUnenrollIsBestEffort(t *testing.T) {
	previousWarn := windowsRouteOnlyWarn
	var warnings []string
	windowsRouteOnlyWarn = func(message string) { warnings = append(warnings, message) }
	t.Cleanup(func() { windowsRouteOnlyWarn = previousWarn })
	removeWindowsRouteOnlyOnUnenroll(InstallOptions{ConnectorName: "cursor", UserHome: t.TempDir()})
	removeWindowsRouteOnlyOnUnenroll(InstallOptions{ConnectorName: "codex"})
	if len(warnings) != 0 {
		t.Fatalf("no-op removals warned: %v", warnings)
	}
	removeWindowsRouteOnlyOnUnenroll(InstallOptions{ConnectorName: "codex", UserHome: filepath.Join(t.TempDir(), "missing"), OwnerSID: "S-1-5-21-1-2-3-4"})
	if len(warnings) != 1 || !strings.Contains(warnings[0], "not restored") {
		t.Fatalf("an unresolvable profile must warn once, got %v", warnings)
	}
}
