// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

var (
	_ ConnectorCapabilityProvider = (*CodexConnector)(nil)
	_ ConnectorCapabilityProvider = (*ClaudeCodeConnector)(nil)
)

func TestCodexCapabilitiesExposeResolvedInventoryAndTelemetry(t *testing.T) {
	home := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	restoreHome, err := BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	t.Setenv("CODEX_HOME", filepath.Join(home, "codex-state"))

	opts := SetupOpts{
		APIAddr:      "127.0.0.1:18970",
		WorkspaceDir: workspace,
	}
	conn := NewCodexConnector()
	caps := conn.Capabilities(opts)

	if caps.LLMTrafficMode != LLMTrafficModeHooksOnly {
		t.Fatalf("LLMTrafficMode=%q want %q", caps.LLMTrafficMode, LLMTrafficModeHooksOnly)
	}
	if !reflect.DeepEqual(caps.Hooks, conn.HookCapabilities(opts)) {
		t.Fatalf("capability hooks drifted from HookCapabilities: got=%+v want=%+v", caps.Hooks, conn.HookCapabilities(opts))
	}
	assertSupportedCapabilitySurfaces(t, caps)
	if !caps.Rules.DiscoveryOnly || !caps.Plugins.DiscoveryOnly || !caps.Agents.DiscoveryOnly {
		t.Fatalf("Codex inventory-only surfaces overclaim writes: rules=%+v plugins=%+v agents=%+v", caps.Rules, caps.Plugins, caps.Agents)
	}
	if !capabilityPathContains(caps.MCP.WritePaths, filepath.Join(workspace, ".codex", "config.toml")) ||
		!capabilityPathContains(caps.MCP.WritePaths, filepath.Join(home, "codex-state", "config.toml")) {
		t.Fatalf("Codex MCP write paths=%v", caps.MCP.WritePaths)
	}
	if !capabilityPathContains(caps.Skills.WritePaths, filepath.Join(home, ".agents", "skills")) {
		t.Fatalf("Codex skill write paths=%v missing personal Agent Skills root", caps.Skills.WritePaths)
	}
	if !caps.CodeGuard.Supported || !reflect.DeepEqual(caps.CodeGuard.InstallTargets, []string{"skill"}) || !caps.CodeGuard.OptInOnly {
		t.Fatalf("Codex CodeGuard capability=%+v", caps.CodeGuard)
	}
	if !caps.Telemetry.NativeOTLP || !reflect.DeepEqual(caps.Telemetry.NativeSignals, []string{"logs", "metrics", "traces"}) ||
		caps.Telemetry.EndpointTemplate != "http://127.0.0.1:18970" {
		t.Fatalf("Codex telemetry capability=%+v", caps.Telemetry)
	}

	locations := ResolvedConnectorLocations(opts, conn)
	assertResolvedNativeCapabilityLocations(t, locations, caps)
}

func TestClaudeCodeCapabilitiesExposeResolvedInventoryAndTelemetry(t *testing.T) {
	home := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	restoreHome, err := BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	claudeHome := filepath.Join(home, "claude-state")
	t.Setenv("CLAUDE_CONFIG_DIR", claudeHome)

	opts := SetupOpts{
		APIAddr:      "127.0.0.1:18970",
		WorkspaceDir: workspace,
	}
	conn := NewClaudeCodeConnector()
	caps := conn.Capabilities(opts)

	if caps.LLMTrafficMode != LLMTrafficModeHooksOnly {
		t.Fatalf("LLMTrafficMode=%q want %q", caps.LLMTrafficMode, LLMTrafficModeHooksOnly)
	}
	if !reflect.DeepEqual(caps.Hooks, conn.HookCapabilities(opts)) {
		t.Fatalf("capability hooks drifted from HookCapabilities: got=%+v want=%+v", caps.Hooks, conn.HookCapabilities(opts))
	}
	assertSupportedCapabilitySurfaces(t, caps)
	if !caps.Rules.DiscoveryOnly || !caps.Plugins.DiscoveryOnly || !caps.Agents.DiscoveryOnly {
		t.Fatalf("Claude inventory-only surfaces overclaim writes: rules=%+v plugins=%+v agents=%+v", caps.Rules, caps.Plugins, caps.Agents)
	}
	wantMCPState := filepath.Join(claudeHome, ".claude.json")
	if !reflect.DeepEqual(caps.MCP.WritePaths, []string{wantMCPState}) {
		t.Fatalf("Claude MCP write paths=%v want only %q", caps.MCP.WritePaths, wantMCPState)
	}
	if !capabilityPathContains(caps.Skills.WritePaths, filepath.Join(workspace, ".claude", "skills")) ||
		!capabilityPathContains(caps.Skills.WritePaths, filepath.Join(claudeHome, "skills")) {
		t.Fatalf("Claude skill write paths=%v", caps.Skills.WritePaths)
	}
	if !caps.CodeGuard.Supported || !reflect.DeepEqual(caps.CodeGuard.InstallTargets, []string{"plugin"}) || !caps.CodeGuard.OptInOnly {
		t.Fatalf("Claude CodeGuard capability=%+v", caps.CodeGuard)
	}
	if !caps.Telemetry.NativeOTLP || !reflect.DeepEqual(caps.Telemetry.NativeSignals, []string{"logs", "metrics"}) ||
		caps.Telemetry.EndpointTemplate != "http://127.0.0.1:18970" {
		t.Fatalf("Claude telemetry capability=%+v", caps.Telemetry)
	}

	locations := ResolvedConnectorLocations(opts, conn)
	assertResolvedNativeCapabilityLocations(t, locations, caps)
}

func assertSupportedCapabilitySurfaces(t *testing.T, caps ConnectorCapabilities) {
	t.Helper()
	for name, surface := range map[string]SurfaceCapability{
		"mcp": caps.MCP, "skills": caps.Skills, "rules": caps.Rules,
		"plugins": caps.Plugins, "agents": caps.Agents,
	} {
		if !surface.Supported {
			t.Errorf("%s surface is not supported: %+v", name, surface)
		}
		if len(surface.ReadPaths) == 0 && len(surface.ConfigPaths) == 0 {
			t.Errorf("%s surface has no resolved inventory paths: %+v", name, surface)
		}
	}
}

func assertResolvedNativeCapabilityLocations(t *testing.T, locations ConnectorLocations, caps ConnectorCapabilities) {
	t.Helper()
	if len(locations.TelemetryConfigPaths) != 1 || locations.TelemetryConfigPaths[0] != caps.Telemetry.ConfigPaths[0] {
		t.Fatalf("telemetry locations=%v want %v", locations.TelemetryConfigPaths, caps.Telemetry.ConfigPaths)
	}
	if len(locations.Surfaces) != 5 {
		t.Fatalf("resolved surfaces=%v want all five capability surfaces", locations.Surfaces)
	}
	for _, name := range []string{"mcp", "skills", "rules", "plugins", "agents"} {
		surface := locations.Surfaces[name]
		if !surface.Supported {
			t.Errorf("resolved %s surface=%+v", name, surface)
		}
		for field, values := range map[string][]string{
			"config_paths":    surface.ConfigPaths,
			"read_paths":      surface.ReadPaths,
			"write_paths":     surface.WritePaths,
			"install_targets": surface.InstallTargets,
		} {
			if len(values) == 0 && values != nil {
				t.Errorf("resolved %s.%s is empty-but-non-nil; lock JSON round trips must remain comparable", name, field)
			}
		}
	}
}

func capabilityPathContains(paths []string, want string) bool {
	want = filepath.Clean(want)
	for _, path := range paths {
		if filepath.Clean(path) == want {
			return true
		}
	}
	return false
}
