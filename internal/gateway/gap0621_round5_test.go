// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// g621PathOnlyFixture is a refused project root linked outside the profile
// that the gateway cannot traverse, with an ordinary same-name user skill.
func g621PathOnlyFixture(t *testing.T) (home, project, root, targetRoot, ordinary string) {
	t.Helper()
	home = t.TempDir()
	project = filepath.Join(home, "project")
	parent := filepath.Join(project, ".claude")
	root = filepath.Join(parent, "skills")
	targetRoot = t.TempDir()
	ordinary = filepath.Join(home, ".claude", "skills", "sample")
	for _, dir := range []string{parent, filepath.Join(targetRoot, "sample"), ordinary} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{filepath.Join(targetRoot, "sample"), ordinary} {
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(targetRoot, root); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	if err := os.Chmod(parent, 0); err != nil {
		t.Skipf("profile access simulation unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	if _, err := filepath.EvalSymlinks(root); err == nil {
		t.Skip("gateway can resolve protected root")
	}
	oldCheck := gatewaySkillPathCheck
	gatewaySkillPathCheck = func(path string) error {
		if insideHome(home, path) {
			return errors.New("gateway cannot inspect caller profile")
		}
		return nil
	}
	t.Cleanup(func() { gatewaySkillPathCheck = oldCheck })
	return home, project, root, targetRoot, ordinary
}

func g621PathOnlyAPI(t *testing.T, mode, root string) *APIServer {
	t.Helper()
	policy := config.DefaultAssetPolicy()
	policy.Mode = mode
	store, logger := newNativeSkillRuntimeTestStore(t)
	api := &APIServer{scannerCfg: &config.Config{AssetPolicy: policy}, store: store, logger: logger, projectSkills: &projectSkillRoots{}}
	api.projectSkills.start(true)
	api.projectSkills.refuseWithPolicyMode(root, "outside caller profile", time.Now(), true)
	return api
}

// REVIEW-4: a path-only Skill call that names the refused link's resolved
// target is accepted by the gateway parser and refused with the facts the
// caller now sends for it (hookpaths TestGAP0621CallerSelectionFormsBindRefusedRoot
// proves the caller side).
func TestReviewG621R4PathOnlySelectedProtectedSkill(t *testing.T) {
	home, project, root, targetRoot, _ := g621PathOnlyFixture(t)
	targetSkill := filepath.Join(targetRoot, "sample")
	alias := filepath.Join(t.TempDir(), "alternate-skill")
	if err := os.Symlink(targetSkill, alias); err != nil {
		t.Skipf("skill alias unavailable: %v", err)
	}
	selectedSample := hookpaths.ProjectSkillSelectedPrefix + filepath.Join(root, "sample")
	for _, mode := range []string{config.AssetPolicyModeAction, config.AssetPolicyModeObserve} {
		t.Run(mode, func(t *testing.T) {
			api := g621PathOnlyAPI(t, mode, root)
			for _, tc := range []struct {
				name     string
				input    map[string]interface{}
				source   string
				selected map[string]string
			}{
				{"skill-path-only-folder", map[string]interface{}{"skill_path": targetSkill}, targetSkill,
					map[string]string{selectedSample: "sample"}},
				{"skill-string-path-folder", map[string]interface{}{"skill": targetSkill}, targetSkill,
					map[string]string{selectedSample: "sample"}},
				{"nested-skill-path-only", map[string]interface{}{"skill": map[string]interface{}{"path": targetSkill}}, targetSkill,
					map[string]string{selectedSample: "sample"}},
				{"path-only-manifest", map[string]interface{}{"skill_path": filepath.Join(targetSkill, "SKILL.md")},
					filepath.Join(targetSkill, "SKILL.md"), map[string]string{selectedSample: "sample"}},
				{"path-only-alias", map[string]interface{}{"skill_path": alias}, alias,
					map[string]string{selectedSample: "alternate-skill"}},
				{"path-only-resolved-root", map[string]interface{}{"skill_path": targetRoot}, targetRoot,
					map[string]string{hookpaths.ProjectSkillSelectedPrefix + root: filepath.Base(targetRoot)}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					probe := skillProbeFromFields("Skill", tc.input, nil)
					if !probe.Matched || probe.SourcePath != tc.source {
						t.Fatalf("gateway did not accept explicit path: %+v", probe)
					}
					facts := map[string]string{hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootOutsideProfile}
					for key, value := range tc.selected {
						facts[key] = value
					}
					ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
					ctx = context.WithValue(ctx, resolvedWritesContextKey{}, facts)
					decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
						HookEventName: "PreToolUse", ToolName: "Skill", CWD: project, ToolInput: tc.input,
					})
					if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
						t.Errorf("protected path-only selection allowed: %+v matched=%v", decision, matched)
					}
				})
			}
		})
	}
}

// The benign twin: a path-only call to an ordinary same-name user skill
// carries only the root finding and keeps loading.
func TestGAP0621R5PathOnlyOrdinarySkillAllowed(t *testing.T) {
	home, project, root, _, ordinary := g621PathOnlyFixture(t)
	api := g621PathOnlyAPI(t, config.AssetPolicyModeAction, root)
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	ctx = context.WithValue(ctx, resolvedWritesContextKey{}, map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootOutsideProfile,
	})
	for _, input := range []map[string]interface{}{
		{"skill_path": ordinary},
		{"skill": ordinary},
		{"skill": map[string]interface{}{"path": ordinary}},
		{"skill_path": filepath.Join(ordinary, "SKILL.md")},
	} {
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project, ToolInput: input,
		})
		if matched && decision.Action == "block" {
			t.Errorf("ordinary path-only skill %v was refused: %+v", input, decision)
		}
	}
}
