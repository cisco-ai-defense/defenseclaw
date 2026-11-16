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

// A managed gateway can know the caller-selected folder and the refused
// project root even when it cannot resolve the root's junction itself.
func TestGAP0621R4UnreadableRootResolvedTarget(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	parent := filepath.Join(project, ".claude")
	root := filepath.Join(parent, "skills")
	targetRoot := t.TempDir()
	targetSkill := filepath.Join(targetRoot, "sample")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(targetSkill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetSkill, "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetRoot, root); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	if err := os.Chmod(parent, 0); err != nil {
		t.Skipf("profile access simulation unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	if _, err := filepath.EvalSymlinks(root); err == nil {
		t.Skip("gateway can still resolve the protected root")
	}
	oldCheck := gatewaySkillPathCheck
	gatewaySkillPathCheck = func(path string) error {
		if insideHome(home, path) {
			return errors.New("gateway cannot inspect caller profile")
		}
		return nil
	}
	t.Cleanup(func() { gatewaySkillPathCheck = oldCheck })
	for _, mode := range []string{config.AssetPolicyModeAction, config.AssetPolicyModeObserve} {
		t.Run(mode, func(t *testing.T) {
			policy := config.DefaultAssetPolicy()
			policy.Mode = mode
			store, logger := newNativeSkillRuntimeTestStore(t)
			api := &APIServer{scannerCfg: &config.Config{AssetPolicy: policy}, store: store, logger: logger, projectSkills: &projectSkillRoots{}}
			api.projectSkills.start(true)
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
			ctx = context.WithValue(ctx, resolvedWritesContextKey{}, map[string]string{
				hookpaths.ProjectSkillRootUnverifiedPrefix + root:                    hookpaths.ProjectSkillRootOutsideProfile,
				hookpaths.ProjectSkillSelectedPrefix + filepath.Join(root, "sample"): "sample",
			})
			api.projectSkills.refuseWithPolicyMode(root, "outside caller profile", time.Now(), true)
			for _, source := range []string{targetRoot, targetSkill, filepath.Join(targetSkill, "SKILL.md")} {
				decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
					ToolInput: map[string]interface{}{"skill": "sample", "skill_path": source},
				})
				if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
					t.Errorf("selected protected target %q = %+v matched=%v; want project-skill-unverified block", source, decision, matched)
				}
			}
		})
	}
}

// The selected name and folder are known, while skill_path names the
// refused project-skill link itself rather than one of its children.
func TestGAP0621R4SelectedRootLinkItself(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	targetRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(targetRoot, "sample"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetRoot, "sample", "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetRoot, root); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	policy := config.DefaultAssetPolicy()
	policy.Mode = config.AssetPolicyModeAction
	store, logger := newNativeSkillRuntimeTestStore(t)
	api := &APIServer{scannerCfg: &config.Config{AssetPolicy: policy}, store: store, logger: logger, projectSkills: &projectSkillRoots{}}
	api.projectSkills.start(true)
	api.projectSkills.refuseWithPolicyMode(root, "outside caller profile", time.Now(), true)
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	ctx = context.WithValue(ctx, resolvedWritesContextKey{}, map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root:                    hookpaths.ProjectSkillRootOutsideProfile,
		hookpaths.ProjectSkillSelectedPrefix + filepath.Join(root, "sample"): "sample",
	})
	decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
		ToolInput: map[string]interface{}{"skill": "sample", "skill_path": root},
	})
	if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
		t.Errorf("selected protected project-skill link = %+v matched=%v; want project-skill-unverified block", decision, matched)
	}
}

func TestGAP0621R4OrdinarySameNameExplicitPathAllowed(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	selected := filepath.Join(root, "sample")
	ordinary := filepath.Join(home, ".claude", "skills", "sample")
	for _, dir := range []string{selected, ordinary} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldCheck := gatewaySkillPathCheck
	gatewaySkillPathCheck = func(path string) error {
		if insideHome(home, path) {
			return errors.New("profile excluded")
		}
		return nil
	}
	t.Cleanup(func() { gatewaySkillPathCheck = oldCheck })
	policy := config.DefaultAssetPolicy()
	policy.Mode = config.AssetPolicyModeAction
	store, logger := newNativeSkillRuntimeTestStore(t)
	api := &APIServer{scannerCfg: &config.Config{AssetPolicy: policy}, store: store, logger: logger, projectSkills: &projectSkillRoots{}}
	api.projectSkills.start(true)
	api.projectSkills.refuseWithPolicyMode(root, "outside caller profile", time.Now(), true)
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	ctx = context.WithValue(ctx, resolvedWritesContextKey{}, map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootOutsideProfile,
	})
	decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
		ToolInput: map[string]interface{}{"skill": "sample", "skill_path": ordinary},
	})
	if matched && decision.Action == "block" {
		t.Fatalf("ordinary explicit skill was refused: %+v", decision)
	}
}
