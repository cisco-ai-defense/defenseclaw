// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestRunWatcherWithoutConfiguredDirectoriesRemainsHealthy(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Gateway.Watcher.Enabled = true
	cfg.Gateway.Watcher.Skill.Enabled = false
	cfg.Gateway.Watcher.Plugin.Enabled = false

	health := NewSidecarHealth()
	sidecar := &Sidecar{cfg: cfg, health: health}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := sidecar.runWatcher(ctx); err != nil {
		t.Fatalf("runWatcher() error = %v", err)
	}
	snap := health.Snapshot()
	if snap.Watcher.State != StateRunning {
		t.Fatalf("watcher state = %q, want %q", snap.Watcher.State, StateRunning)
	}
	if snap.Watcher.LastError != "" {
		t.Fatalf("watcher error = %q, want empty", snap.Watcher.LastError)
	}
	if got := snap.Watcher.Details["idle"]; got != "no directories configured" {
		t.Fatalf("watcher idle detail = %v", got)
	}
}

// TestResolveWatcherDirs_PerConnectorMatrix is the C4 / S1.3 matrix
// test the plan calls for: prove that for every built-in connector,
// runWatcher's dir-resolution helper actually pulls the directories
// from that connector's ComponentScanner — not from a hardcoded
// OpenClaw fallback. This is what guarantees the "watcher follows
// the active connector" promise across openclaw / zeptoclaw /
// claudecode / codex.
//
// Each row asserts:
//  1. resolveWatcherDirs returned watcherDirsFromConnector for both
//     the skill and plugin buckets — meaning the priority chain
//     selected ComponentTargets and not cfg.SkillDirs() default.
//  2. The skill/plugin slices contain at least one path under the
//     connector-owned home directory (e.g. "~/.codex/skills" for
//     codex). Path equality across $HOME is brittle — substring
//     check on the connector's expected home subpath is the
//     stable assertion.
func TestResolveWatcherDirs_PerConnectorMatrix(t *testing.T) {
	cases := []struct {
		name             string
		ctor             func() connector.Connector
		expectSkillFrag  string // substring expected in at least one skill dir
		expectPluginFrag string // substring expected in at least one plugin dir
	}{
		{
			name:             "openclaw",
			ctor:             func() connector.Connector { return connector.NewOpenClawConnector() },
			expectSkillFrag:  filepath.Join(".openclaw", "workspace", "skills"),
			expectPluginFrag: filepath.Join(".openclaw", "extensions"),
		},
		{
			name:             "zeptoclaw",
			ctor:             func() connector.Connector { return connector.NewZeptoClawConnector() },
			expectSkillFrag:  filepath.Join(".zeptoclaw", "skills"),
			expectPluginFrag: filepath.Join(".zeptoclaw", "plugins"),
		},
		{
			name:             "claudecode",
			ctor:             func() connector.Connector { return connector.NewClaudeCodeConnector() },
			expectSkillFrag:  filepath.Join(".claude", "skills"),
			expectPluginFrag: filepath.Join(".claude", "plugins"),
		},
		{
			name:             "codex",
			ctor:             func() connector.Connector { return connector.NewCodexConnector() },
			expectSkillFrag:  filepath.Join(".codex", "skills"),
			expectPluginFrag: filepath.Join(".codex", "plugins"),
		},
	}

	wcfg := config.GatewayWatcherConfig{}
	wcfg.Skill.Enabled = true
	wcfg.Plugin.Enabled = true
	cfg := &config.Config{}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn := tc.ctor()
			skillDirs, pluginDirs, src := resolveWatcherDirs(cfg, conn, wcfg)

			if src.Skill != watcherDirsFromConnector {
				t.Errorf("skill source = %q, want %q (the connector's ComponentTargets must win over defaults)",
					src.Skill, watcherDirsFromConnector)
			}
			if src.Plugin != watcherDirsFromConnector {
				t.Errorf("plugin source = %q, want %q",
					src.Plugin, watcherDirsFromConnector)
			}

			if !anyContains(skillDirs, tc.expectSkillFrag) {
				t.Errorf("skill dirs %v do not contain %q (connector ComponentTargets misrouted?)",
					skillDirs, tc.expectSkillFrag)
			}
			if !anyContains(pluginDirs, tc.expectPluginFrag) {
				t.Errorf("plugin dirs %v do not contain %q",
					pluginDirs, tc.expectPluginFrag)
			}
		})
	}
}

// TestResolveWatcherDirs_ExplicitConfigBeatsConnector pins the priority
// chain: an operator-supplied gateway.watcher.skill.dirs MUST take
// precedence over the connector's autodiscovered list. Without this,
// a user override is silently ignored when a connector also has
// ComponentTargets("skill").
func TestResolveWatcherDirs_ExplicitConfigBeatsConnector(t *testing.T) {
	t.Parallel()
	conn := connector.NewClaudeCodeConnector()

	wcfg := config.GatewayWatcherConfig{}
	wcfg.Skill.Enabled = true
	wcfg.Skill.Dirs = []string{"/srv/explicit/skills"}
	wcfg.Plugin.Enabled = true
	wcfg.Plugin.Dirs = []string{"/srv/explicit/plugins"}

	cfg := &config.Config{}
	skillDirs, pluginDirs, src := resolveWatcherDirs(cfg, conn, wcfg)

	if src.Skill != watcherDirsFromConfig {
		t.Errorf("skill source = %q, want %q", src.Skill, watcherDirsFromConfig)
	}
	if src.Plugin != watcherDirsFromConfig {
		t.Errorf("plugin source = %q, want %q", src.Plugin, watcherDirsFromConfig)
	}
	if len(skillDirs) != 1 || skillDirs[0] != "/srv/explicit/skills" {
		t.Errorf("skill dirs = %v, want [/srv/explicit/skills]", skillDirs)
	}
	if len(pluginDirs) != 1 || pluginDirs[0] != "/srv/explicit/plugins" {
		t.Errorf("plugin dirs = %v, want [/srv/explicit/plugins]", pluginDirs)
	}
}

// TestResolveWatcherDirs_DisabledStaysEmpty confirms the disabled
// path: when a bucket is disabled, no dirs flow through and the
// source tag reflects "disabled" so the caller can short-circuit
// telemetry/log lines.
func TestResolveWatcherDirs_DisabledStaysEmpty(t *testing.T) {
	t.Parallel()
	conn := connector.NewClaudeCodeConnector()
	wcfg := config.GatewayWatcherConfig{}
	wcfg.Skill.Enabled = false
	wcfg.Plugin.Enabled = false

	cfg := &config.Config{}
	skillDirs, pluginDirs, src := resolveWatcherDirs(cfg, conn, wcfg)

	if len(skillDirs) != 0 {
		t.Errorf("skill dirs = %v, want empty when disabled", skillDirs)
	}
	if len(pluginDirs) != 0 {
		t.Errorf("plugin dirs = %v, want empty when disabled", pluginDirs)
	}
	if src.Skill != watcherDirsDisabled || src.Plugin != watcherDirsDisabled {
		t.Errorf("sources = %+v, want both watcherDirsDisabled", src)
	}
}

// TestResolveWatcherDirs_NilConnectorFallsBackToConfigDefault covers
// the resolveActiveConnector failure branch in runWatcher: the
// helper logs and falls through with conn=nil. The watcher must
// not crash and must emit the default cfg dirs (OpenClaw).
func TestResolveWatcherDirs_NilConnectorFallsBackToConfigDefault(t *testing.T) {
	t.Parallel()
	wcfg := config.GatewayWatcherConfig{}
	wcfg.Skill.Enabled = true
	wcfg.Plugin.Enabled = true

	cfg := &config.Config{}
	_, _, src := resolveWatcherDirs(cfg, nil, wcfg)

	if src.Skill != watcherDirsFromDefault {
		t.Errorf("skill source = %q, want %q (nil connector must trip the cfg fallback)",
			src.Skill, watcherDirsFromDefault)
	}
	if src.Plugin != watcherDirsFromDefault {
		t.Errorf("plugin source = %q, want %q",
			src.Plugin, watcherDirsFromDefault)
	}
}

// TestResolveWatcherDirs_HookOnlyConnectorMatrix locks the watcher
// contract for the six hook-only connectors (hermes, cursor,
// windsurf, geminicli, copilot, openhands). Two contracts differ from the
// claudecode/codex matrix above and are pinned here:
//
//  1. Plugins is OpenClaw-only (G4): every hook-only connector
//     advertises Plugins.Supported=false, so resolveWatcherDirs
//     MUST fall back to cfg.PluginDirs() with src.Plugin=
//     watcherDirsFromDefault. A regression that lets a hook-only
//     connector contribute plugin paths would silently begin
//     watching directories that the connector itself does not
//     own — exactly the behavior we eliminated.
//
//  2. Skills support varies: hermes/cursor/geminicli/copilot/openhands
//     advertise their own skill paths so src.Skill must be
//     watcherDirsFromConnector and the slice must contain a
//     framework-owned subpath. windsurf intentionally does NOT
//     advertise a skills surface ("Windsurf skills are not exposed
//     as a documented local install surface."), so it falls back to
//     watcherDirsFromDefault. This split is what justifies a
//     dedicated matrix rather than reusing the openclaw/zeptoclaw/
//     claudecode/codex one above.
func TestResolveWatcherDirs_HookOnlyConnectorMatrix(t *testing.T) {
	cases := []struct {
		name            string
		ctor            func() connector.Connector
		expectSkillSrc  watcherDirSource
		expectSkillFrag string // empty when expectSkillSrc != watcherDirsFromConnector
	}{
		{
			name:            "hermes",
			ctor:            func() connector.Connector { return connector.NewHermesConnector() },
			expectSkillSrc:  watcherDirsFromConnector,
			expectSkillFrag: filepath.Join(".hermes", "skills"),
		},
		{
			name:            "cursor",
			ctor:            func() connector.Connector { return connector.NewCursorConnector() },
			expectSkillSrc:  watcherDirsFromConnector,
			expectSkillFrag: filepath.Join(".cursor", "skills"),
		},
		{
			name:           "windsurf",
			ctor:           func() connector.Connector { return connector.NewWindsurfConnector() },
			expectSkillSrc: watcherDirsFromDefault,
		},
		{
			name:            "geminicli",
			ctor:            func() connector.Connector { return connector.NewGeminiCLIConnector() },
			expectSkillSrc:  watcherDirsFromConnector,
			expectSkillFrag: filepath.Join(".gemini", "skills"),
		},
		{
			// With no workspace pinned in cfg the connector
			// must surface its user-scope skill directory
			// (~/.copilot/skills) instead of inferring a
			// workspace from the daemon's cwd.
			name:            "copilot",
			ctor:            func() connector.Connector { return connector.NewCopilotConnector() },
			expectSkillSrc:  watcherDirsFromConnector,
			expectSkillFrag: filepath.Join(".copilot", "skills"),
		},
		{
			name:            "openhands",
			ctor:            func() connector.Connector { return connector.NewOpenHandsConnector() },
			expectSkillSrc:  watcherDirsFromConnector,
			expectSkillFrag: filepath.Join(".agents", "skills"),
		},
	}

	wcfg := config.GatewayWatcherConfig{}
	wcfg.Skill.Enabled = true
	wcfg.Plugin.Enabled = true
	cfg := &config.Config{}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn := tc.ctor()
			skillDirs, _, src := resolveWatcherDirs(cfg, conn, wcfg)

			if src.Skill != tc.expectSkillSrc {
				t.Errorf("skill source = %q, want %q", src.Skill, tc.expectSkillSrc)
			}
			if tc.expectSkillFrag != "" && !anyContains(skillDirs, tc.expectSkillFrag) {
				t.Errorf("skill dirs %v do not contain %q (connector ComponentTargets misrouted?)",
					skillDirs, tc.expectSkillFrag)
			}

			// Plugins are OpenClaw-only (G4). Every hook-only
			// connector MUST fall back to the cfg default rather
			// than contributing connector-specific plugin paths.
			if src.Plugin != watcherDirsFromDefault {
				t.Errorf("plugin source = %q, want %q (hook-only connectors must not contribute plugin paths)",
					src.Plugin, watcherDirsFromDefault)
			}
		})
	}
}

func TestResolveWatcherDirs_OpenHandsUsesPinnedWorkspace(t *testing.T) {
	t.Parallel()

	workspace := filepath.Join(t.TempDir(), "repo")
	cfg := &config.Config{
		Claw: config.ClawConfig{WorkspaceDir: workspace},
	}
	wcfg := config.GatewayWatcherConfig{}
	wcfg.Skill.Enabled = true
	wcfg.Plugin.Enabled = true

	skillDirs, _, src := resolveWatcherDirs(cfg, connector.NewOpenHandsConnector(), wcfg)

	if src.Skill != watcherDirsFromConnector {
		t.Fatalf("skill source = %q, want %q", src.Skill, watcherDirsFromConnector)
	}
	if !anyContains(skillDirs, filepath.Join(workspace, ".agents", "skills")) {
		t.Fatalf("OpenHands skill dirs = %v, want pinned workspace %s", skillDirs, workspace)
	}
}

func anyContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}
