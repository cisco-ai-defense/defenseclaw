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

func TestGAP0621R8UserRootAliasToProtectedSkillMustBlock(t *testing.T) {
	home, project, root, targetRoot, _ := g621PathOnlyFixture(t)
	protected := filepath.Join(targetRoot, "sample")
	alias := filepath.Join(home, ".claude", "skills", "outside-alias")
	if err := os.Symlink(protected, alias); err != nil {
		t.Skipf("alias unavailable: %v", err)
	}
	api := g621PathOnlyAPI(t, config.AssetPolicyModeAction, root)
	facts := map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root:                    hookpaths.ProjectSkillRootOutsideProfile,
		hookpaths.ProjectSkillSelectedPrefix + filepath.Join(root, "sample"): "sample",
	}
	for _, source := range []string{alias, filepath.Join(alias, "SKILL.md")} {
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
		ctx = context.WithValue(ctx, resolvedWritesContextKey{}, facts)
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
			ToolInput: map[string]interface{}{"skill": "sample", "skill_path": source},
		})
		if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
			t.Errorf("protected alias %s allowed: matched=%v action=%s source=%s", source, matched, decision.Action, decision.Source)
		}
	}
}

func TestGAP0621R8AliasToPrivateUserSkillMustAllow(t *testing.T) {
	home, project, root, targetRoot, ordinary := g621PathOnlyFixture(t)
	if err := os.Symlink(ordinary, filepath.Join(targetRoot, "zz-private-skill")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "sample")
	if err := os.Symlink(ordinary, alias); err != nil {
		t.Skipf("alias unavailable: %v", err)
	}
	api := g621PathOnlyAPI(t, config.AssetPolicyModeAction, root)
	// The caller sends no selected-folder fact for a skill its profile holds
	// privately (hookpaths TestGAP0621R8DirectLinkToPrivateUserSkill).
	facts := map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootOutsideProfile,
	}
	relative, err := filepath.Rel(project, ordinary)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{ordinary, filepath.Join(ordinary, "SKILL.md"), relative, filepath.Join(relative, "SKILL.md"), alias, filepath.Join(alias, "SKILL.md")} {
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
		ctx = context.WithValue(ctx, resolvedWritesContextKey{}, facts)
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
			ToolInput: map[string]interface{}{"skill": "sample", "skill_path": source},
		})
		if matched && decision.Action == "block" {
			t.Errorf("ordinary private alias %s refused: source=%s", source, decision.Source)
		}
	}
}
