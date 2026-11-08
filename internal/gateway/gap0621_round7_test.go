// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// REVIEW-6, gateway half. A qualified name with an explicit protected source
// is refused with the selected-folder fact the caller now sends for it
// (hookpaths TestGAP0621QualifiedNameExplicitSourceBinds proves the caller
// side). An explicit source in the caller's own user skill folder loads that
// skill whatever project fact accompanies it (hookpaths
// TestGAP0621NonskillChildLinkLeavesOrdinarySource proves the caller no
// longer sends one), while the same fact still refuses a protected source.
func TestGAP0621R7SelectionDecisions(t *testing.T) {
	home, project, root, targetRoot, ordinary := g621PathOnlyFixture(t)
	protected := filepath.Join(targetRoot, "sample")
	rootOnly := map[string]string{hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootOutsideProfile}
	with := func(dir, name string) map[string]string {
		facts := map[string]string{hookpaths.ProjectSkillSelectedPrefix + dir: name}
		for key, value := range rootOnly {
			facts[key] = value
		}
		return facts
	}
	for _, mode := range []string{config.AssetPolicyModeAction, config.AssetPolicyModeObserve} {
		t.Run(mode, func(t *testing.T) {
			api := g621PathOnlyAPI(t, mode, root)
			for _, tc := range []struct {
				label string
				input map[string]interface{}
				facts map[string]string
				block bool
			}{
				{"qualified name, protected source", map[string]interface{}{"skill_name": "plugin:sample", "skill_path": protected},
					with(filepath.Join(root, "sample"), "plugin:sample"), true},
				{"qualified name, protected manifest", map[string]interface{}{"skill_name": "plugin:sample", "skill_path": filepath.Join(protected, "SKILL.md")},
					with(filepath.Join(root, "sample"), "plugin:sample"), true},
				{"qualified name, ordinary source", map[string]interface{}{"skill_name": "plugin:sample", "skill_path": ordinary},
					rootOnly, false},
				{"ordinary source, root fact", map[string]interface{}{"skill": "sample", "skill_path": ordinary},
					rootOnly, false},
				{"protected source, project fact", map[string]interface{}{"skill": "sample", "skill_path": protected},
					with(filepath.Join(root, "sample"), "sample"), true},
			} {
				ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
				ctx = context.WithValue(ctx, resolvedWritesContextKey{}, tc.facts)
				decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", ToolName: "Skill", CWD: project, ToolInput: tc.input,
				})
				blocked := matched && decision.Action == "block"
				if !tc.block && blocked {
					t.Errorf("%s: ordinary selection refused: %+v", tc.label, decision)
				}
				if tc.block && (!blocked || decision.Source != "project-skill-unverified") {
					t.Errorf("%s: protected selection allowed: %+v matched=%v", tc.label, decision, matched)
				}
			}
		})
	}
}
