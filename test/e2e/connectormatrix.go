// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// ConnectorFixture is a single per-connector test fixture exposed by
// the connector matrix helper. Tests that want to run the same body
// against every connector iterate “connectorMatrix(t)“ and call
// “fx.Apply(t)“ to seat the per-connector overrides.
//
// Plan E3 / S3.4 — every test that hardcoded "openclaw" today should
// adopt this helper so regressions in other connectors are loud at the
// same level OpenClaw is.
type ConnectorFixture struct {
	// Name is the canonical connector name (matches Connector.Name()).
	Name string
	// DestinationApp is the gatewaylog destination_app label that
	// must show up on egress events for this connector. It is the
	// human-readable framework name the audit / OTel surfaces
	// associate with traffic that passed through ``/c/<name>/``.
	DestinationApp string
	// ClawMode is the legacy ``cfg.Claw.Mode`` value some test
	// fixtures still set instead of ``cfg.Guardrail.Connector``;
	// kept in lockstep with Name for backward compatibility.
	ClawMode string
	// Apply seats per-connector home / config overrides on a fresh
	// tmpdir so the fixture never touches the developer's real
	// $HOME. The cleanup is registered via t.Cleanup automatically.
	Apply func(t *testing.T) (homeDir string, dataDir string)
}

// connectorMatrix returns the canonical fixture set for built-in connectors.
// Tests should pass this through “t.Run“ to
// drive subtests; failing one subtest does not skip the others.
func connectorMatrix(t *testing.T) []ConnectorFixture {
	t.Helper()
	return []ConnectorFixture{
		{
			Name:           "openclaw",
			DestinationApp: "openclaw",
			ClawMode:       "openclaw",
			Apply: func(t *testing.T) (string, string) {
				t.Helper()
				home := t.TempDir()
				prev := connector.OpenClawHomeOverride
				connector.OpenClawHomeOverride = filepath.Join(home, ".openclaw")
				_ = os.MkdirAll(connector.OpenClawHomeOverride, 0o755)
				t.Cleanup(func() { connector.OpenClawHomeOverride = prev })
				return home, t.TempDir()
			},
		},
		{
			Name:           "zeptoclaw",
			DestinationApp: "zeptoclaw",
			ClawMode:       "zeptoclaw",
			Apply: func(t *testing.T) (string, string) {
				t.Helper()
				home := t.TempDir()
				prev := connector.ZeptoClawConfigPathOverride
				connector.ZeptoClawConfigPathOverride = filepath.Join(home, ".zeptoclaw", "config.json")
				t.Cleanup(func() { connector.ZeptoClawConfigPathOverride = prev })
				return home, t.TempDir()
			},
		},
		{
			Name:           "claudecode",
			DestinationApp: "claudecode",
			ClawMode:       "claudecode",
			Apply: func(t *testing.T) (string, string) {
				t.Helper()
				home := t.TempDir()
				prev := connector.ClaudeCodeSettingsPathOverride
				connector.ClaudeCodeSettingsPathOverride = filepath.Join(home, ".claude", "settings.json")
				t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = prev })
				return home, t.TempDir()
			},
		},
		{
			Name:           "codex",
			DestinationApp: "codex",
			ClawMode:       "codex",
			Apply: func(t *testing.T) (string, string) {
				t.Helper()
				home := t.TempDir()
				prev := connector.CodexConfigPathOverride
				connector.CodexConfigPathOverride = filepath.Join(home, ".codex", "config.toml")
				t.Cleanup(func() { connector.CodexConfigPathOverride = prev })
				return home, t.TempDir()
			},
		},
		{
			Name:           "hermes",
			DestinationApp: "hermes",
			ClawMode:       "hermes",
			Apply:          hookOnlyFixtureApply("hermes"),
		},
		{
			Name:           "cursor",
			DestinationApp: "cursor",
			ClawMode:       "cursor",
			Apply:          hookOnlyFixtureApply("cursor"),
		},
		{
			Name:           "windsurf",
			DestinationApp: "windsurf",
			ClawMode:       "windsurf",
			Apply:          hookOnlyFixtureApply("windsurf"),
		},
		{
			Name:           "geminicli",
			DestinationApp: "geminicli",
			ClawMode:       "geminicli",
			Apply:          hookOnlyFixtureApply("geminicli"),
		},
		{
			Name:           "copilot",
			DestinationApp: "copilot",
			ClawMode:       "copilot",
			Apply:          hookOnlyFixtureApply("copilot"),
		},
	}
}

func hookOnlyFixtureApply(name string) func(t *testing.T) (string, string) {
	return func(t *testing.T) (string, string) {
		t.Helper()
		home := t.TempDir()
		switch name {
		case "hermes":
			prev := connector.HermesConfigPathOverride
			connector.HermesConfigPathOverride = filepath.Join(home, ".hermes", "config.yaml")
			t.Cleanup(func() { connector.HermesConfigPathOverride = prev })
		case "cursor":
			prev := connector.CursorHooksPathOverride
			connector.CursorHooksPathOverride = filepath.Join(home, ".cursor", "hooks.json")
			t.Cleanup(func() { connector.CursorHooksPathOverride = prev })
		case "windsurf":
			prev := connector.WindsurfHooksPathOverride
			connector.WindsurfHooksPathOverride = filepath.Join(home, ".codeium", "windsurf", "hooks.json")
			t.Cleanup(func() { connector.WindsurfHooksPathOverride = prev })
		case "geminicli":
			prev := connector.GeminiSettingsPathOverride
			connector.GeminiSettingsPathOverride = filepath.Join(home, ".gemini", "settings.json")
			t.Cleanup(func() { connector.GeminiSettingsPathOverride = prev })
		case "copilot":
			prev := connector.CopilotHooksPathOverride
			connector.CopilotHooksPathOverride = filepath.Join(home, "workspace", ".github", "hooks", "defenseclaw.json")
			t.Cleanup(func() { connector.CopilotHooksPathOverride = prev })
		}
		return home, t.TempDir()
	}
}
