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

// REVIEW-8: the project root is a link to the caller private skill and the
// gateway cannot read the caller profile. Naming the private skill by its
// own folder or manifest is allowed with the facts the caller sends (the root
// fact only); naming the project link is still refused.
func TestGAP0621R9PrivateSkillAsLinkedRoot(t *testing.T) {
	home := t.TempDir()
	private := filepath.Join(home, ".claude", "skills", "sample")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(private, "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(private, root); err != nil {
		t.Skipf("root link unavailable: %v", err)
	}
	// Simulate the managed gateway lacking access to the caller profile.
	profileSkills := filepath.Join(home, ".claude", "skills")
	if err := os.Chmod(profileSkills, 0); err != nil {
		t.Skipf("profile access simulation unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(profileSkills, 0o700) })
	if _, err := filepath.EvalSymlinks(private); err == nil {
		t.Skip("gateway can resolve the private skill")
	}
	api := g621PathOnlyAPI(t, config.AssetPolicyModeAction, root)
	decide := func(facts map[string]string, source string) (bool, config.AssetPolicyDecision) {
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
		ctx = context.WithValue(ctx, resolvedWritesContextKey{}, facts)
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
			ToolInput: map[string]interface{}{"skill": "sample", "skill_path": source},
		})
		return matched, decision
	}
	rootFact := map[string]string{hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootSharedWritable}
	for _, source := range []string{private, filepath.Join(private, "SKILL.md")} {
		if matched, got := decide(rootFact, source); matched && got.Action == "block" {
			t.Errorf("private source %s refused: source=%s", source, got.Source)
		}
	}
	linked := map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootSharedWritable,
		hookpaths.ProjectSkillSelectedPrefix + root:       "sample",
	}
	if matched, got := decide(linked, root); !matched || got.Action != "block" || got.Source != "project-skill-unverified" {
		t.Errorf("call naming the project link allowed: matched=%v action=%s source=%s", matched, got.Action, got.Source)
	}
}
