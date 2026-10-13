// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestHookAIDInspectUsesReloadedSurface(t *testing.T) {
	disabled, enabled := false, true
	startup := &config.Config{CiscoAIDefense: config.CiscoAIDefenseConfig{ScanHookSurface: &disabled}}
	live := &config.Config{CiscoAIDefense: config.CiscoAIDefenseConfig{ScanHookSurface: &enabled}}
	inspector := &stubAIDInspector{verdict: blockVerdict()}
	api := &APIServer{scannerCfg: startup, ciscoInspector: inspector}
	api.SetGenerationSource(func() *Generation { return &Generation{Config: live} })

	if got := api.hookAIDInspect(t.Context(), "Bash", "dc_reload_marker"); got == nil || got.Action != "block" {
		t.Fatalf("reloaded hook surface verdict = %+v, want block", got)
	}
	if inspector.calls != 1 {
		t.Fatalf("AI Defense calls = %d, want 1", inspector.calls)
	}
}

func TestManagedAIDOnlyUsesReloadedHookSurface(t *testing.T) {
	disabled, enabled := false, true
	startup := &config.Config{CiscoAIDefense: config.CiscoAIDefenseConfig{ScanHookSurface: &disabled}}
	live := &config.Config{CiscoAIDefense: config.CiscoAIDefenseConfig{ScanHookSurface: &enabled}}
	inspector := &stubAIDInspector{verdict: blockVerdict()}
	api := &APIServer{scannerCfg: startup, ciscoInspector: inspector}
	api.SetGenerationSource(func() *Generation { return &Generation{Config: live} })

	if got := api.inspectManagedAIDOnly(t.Context(), "Bash", "dc_reload_marker"); got == nil || got.Action != "block" {
		t.Fatalf("managed reloaded hook verdict = %+v, want block", got)
	}
	if inspector.calls != 1 {
		t.Fatalf("AI Defense calls = %d, want 1", inspector.calls)
	}
}

func TestStopScansUseReloadedPathsAndCodeGuardRules(t *testing.T) {
	target := filepath.Join(t.TempDir(), "marker.py")
	if err := os.WriteFile(target, []byte("DC_RELOAD_MARKER\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldRules := t.TempDir()
	newRules := t.TempDir()
	rule := "version: 1\nrules:\n  - id: CG-RELOAD-001\n    severity: high\n    title: Reload marker\n    pattern: DC_RELOAD_MARKER\n    extensions: [.py]\n"
	if err := os.WriteFile(filepath.Join(newRules, "marker.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		scan func(*APIServer) *ToolInspectVerdict
	}{
		{"claudecode", func(a *APIServer) *ToolInspectVerdict {
			return a.scanClaudeCodeChangedFiles(context.Background(), claudeCodeHookRequest{})
		}},
		{"codex", func(a *APIServer) *ToolInspectVerdict {
			return a.scanCodexChangedFiles(context.Background(), codexHookRequest{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			startup := &config.Config{Scanners: config.ScannersConfig{CodeGuard: oldRules}}
			live := &config.Config{
				Scanners:       config.ScannersConfig{CodeGuard: newRules},
				ConnectorHooks: map[string]config.AgentHookConfig{tc.name: {ScanPaths: []string{target}}},
			}
			api := &APIServer{scannerCfg: startup}
			api.SetGenerationSource(func() *Generation { return &Generation{Config: live} })
			got := tc.scan(api)
			if got == nil || got.Action != "block" || len(got.Findings) != 1 || got.Findings[0] != "CG-RELOAD-001" {
				t.Fatalf("reloaded stop scan = %+v, want CG-RELOAD-001 block", got)
			}
		})
	}
}

func TestMalformedAssetIdentityUsesReloadedActionMode(t *testing.T) {
	startup := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	startup.AssetPolicy.Enabled = true
	startup.AssetPolicy.Mode = "observe"
	live := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	live.AssetPolicy.Enabled = true
	live.AssetPolicy.Mode = "action"
	store, logger := newNativeSkillRuntimeTestStore(t)
	api := &APIServer{scannerCfg: startup, store: store, logger: logger}
	api.SetGenerationSource(func() *Generation { return &Generation{Config: live} })

	decisions := api.claudeCodeSlashCommandAssetDecisions(t.Context(), claudeCodeHookRequest{
		HookEventName: "UserPromptExpansion",
		ExpansionType: "slash_command",
		CommandName:   "sample",
		CommandSource: "skill",
		Prompt:        "/different",
	})
	if len(decisions) != 1 || decisions[0].decision.Source != "runtime-identity-error" || decisions[0].decision.Action != "block" {
		t.Fatalf("reloaded malformed asset decision = %+v, want identity block", decisions)
	}
}
