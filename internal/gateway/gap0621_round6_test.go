// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// REVIEW-5, gateway half. Each case passes the facts the caller sends for the
// call (hookpaths TestGAP0621LinkedChildAfterManyEntriesBinds,
// TestGAP0621LargeRootNameOnlySelectionIsExact and
// TestGAP0621TopLevelNameUsesEveryExplicitSource prove the caller side):
// the ordinary selections carry only the root finding and keep loading, the
// protected ones carry the selected folder and are refused.
func TestGAP0621R6SelectionDecisionsWithCallerFacts(t *testing.T) {
	home, project, root, targetRoot, ordinary := g621PathOnlyFixture(t)
	protected := filepath.Join(t.TempDir(), "protected")
	if err := os.MkdirAll(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(protected, "SKILL.md"), []byte("---\nname: protected\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(targetRoot, "zz-linked-skill")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
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
				label   string
				payload map[string]interface{}
				input   map[string]interface{}
				facts   map[string]string
				block   bool
			}{
				{"top-level name, ordinary input path", map[string]interface{}{"skill": "sample"},
					map[string]interface{}{"skill": "sample", "skill_path": ordinary}, rootOnly, false},
				{"large root, ordinary name only", nil, map[string]interface{}{"skill": "sample"}, rootOnly, false},
				{"top-level name, project input path", map[string]interface{}{"skill": "sample"},
					map[string]interface{}{"skill": "sample", "skill_path": filepath.Join(root, "sample")},
					with(filepath.Join(root, "sample"), "sample"), true},
				{"linked child target", nil, map[string]interface{}{"skill_path": protected},
					with(filepath.Join(root, "zz-linked-skill"), "protected"), true},
				{"linked child manifest", nil, map[string]interface{}{"skill_path": filepath.Join(protected, "SKILL.md")},
					with(filepath.Join(root, "zz-linked-skill"), "protected"), true},
			} {
				ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
				ctx = context.WithValue(ctx, resolvedWritesContextKey{}, tc.facts)
				decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
					Payload: tc.payload, ToolInput: tc.input,
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
