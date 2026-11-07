// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0613: a root several connectors load applies each consumer connector
// scoped asset rules to what lands there, not only the event owner rules.
func TestGAP0613RootConsumersApplyTheirOwnAssetRules(t *testing.T) {
	root := filepath.Join(t.TempDir(), "skills")
	other := filepath.Join(t.TempDir(), "skills")
	cfg := config.DefaultConfig()
	cfg.AssetPolicy = config.DefaultAssetPolicy()
	input := func(connector string) config.AssetPolicyInput {
		return config.AssetPolicyInput{TargetType: "skill", Name: "blocked-skill", Connector: connector, RuntimeSurface: "watcher"}
	}
	for _, tc := range []struct {
		name      string
		consumers []RootConsumer
		rule      string
		path      string
		blocked   bool
		by        string
	}{
		{"second-consumer-rule", []RootConsumer{{"skill", root, "amp"}, {"skill", root, "codex"}}, "codex", filepath.Join(root, "blocked-skill"), true, "codex"},
		{"third-consumer-rule", []RootConsumer{{"skill", root, "amp"}, {"skill", root, "codex"}, {"skill", root, "kiro"}}, "kiro", filepath.Join(root, "blocked-skill"), true, "kiro"},
		{"owner-rule", []RootConsumer{{"skill", root, "amp"}, {"skill", root, "codex"}}, "amp", filepath.Join(root, "blocked-skill"), true, "amp"},
		{"nested-skill-file-path", []RootConsumer{{"skill", root, "amp"}, {"skill", root, "codex"}}, "codex", filepath.Join(root, "blocked-skill", "SKILL.md"), true, "codex"},
		{"connector-that-does-not-load-the-root", []RootConsumer{{"skill", root, "amp"}, {"skill", root, "codex"}}, "cursor", filepath.Join(root, "blocked-skill"), false, "amp"},
		{"same-connector-loads-another-root-only", []RootConsumer{{"skill", root, "amp"}, {"skill", other, "codex"}}, "codex", filepath.Join(root, "blocked-skill"), false, "amp"},
		{"plugin-root-is-not-a-skill-root", []RootConsumer{{"skill", root, "amp"}, {"plugin", root, "codex"}}, "codex", filepath.Join(root, "blocked-skill"), false, "amp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := *cfg
			cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "blocked-skill", Connector: tc.rule, Reason: "protected"}}
			w := &InstallWatcher{}
			w.SetRootConsumers(tc.consumers)
			evt := InstallEvent{Type: InstallSkill, Name: "blocked-skill", Path: tc.path}
			decision, by := w.evaluateRootAssetPolicy(&cfg, evt, "amp", input)
			if got := decision.Enabled && decision.RawAction == "block" && decision.Action == "block"; got != tc.blocked {
				t.Fatalf("blocked = %v (decision %+v), want %v", got, decision, tc.blocked)
			}
			if by != tc.by {
				t.Errorf("decision connector = %q, want %q", by, tc.by)
			}
		})
	}
}

func TestGAP0613RootConsumersOfKeepsOwnerFirstAndSkipsMCP(t *testing.T) {
	root := t.TempDir()
	w := &InstallWatcher{}
	w.SetRootConsumers([]RootConsumer{{"skill", root, "codex"}, {"skill", root, "amp"}, {"skill", root, "codex"}})
	got := w.rootConsumersOf(InstallEvent{Type: InstallSkill, Path: filepath.Join(root, "s")}, "amp")
	if !slices.Equal(got, []string{"amp", "codex"}) {
		t.Errorf("consumers = %v, want [amp codex]", got)
	}
	if got := w.rootConsumersOf(InstallEvent{Type: InstallMCP, Path: filepath.Join(root, "s")}, "amp"); !slices.Equal(got, []string{"amp"}) {
		t.Errorf("MCP consumers = %v, want only the owner", got)
	}
}
