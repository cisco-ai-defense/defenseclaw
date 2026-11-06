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

// TestReviewG621R2NestedProtectedPathStaysBlocked covers descendants of the
// selected skill folder, rather than only its folder and top-level manifest.
func TestReviewG621R2NestedProtectedPathStaysBlocked(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	skill := filepath.Join(root, "sample")
	refs := filepath.Join(skill, "refs")
	if err := os.MkdirAll(refs, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(refs, "guide.md")
	if err := os.WriteFile(file, []byte("protected skill reference"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(skill, "SKILL.md")
	if err := os.WriteFile(manifest, []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(refs, "guide-link.md")
	linkErr := os.Symlink(file, link)
	alias := filepath.Join(project, "skill-alias")
	aliasErr := os.Symlink(skill, alias)
	manifestAliasDir := filepath.Join(project, "manifest-alias")
	if err := os.MkdirAll(manifestAliasDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifestAlias := filepath.Join(manifestAliasDir, "SKILL.md")
	manifestAliasErr := os.Symlink(manifest, manifestAlias)
	oldCheck := gatewaySkillPathCheck
	gatewaySkillPathCheck = func(path string) error {
		if insideHome(home, path) {
			return errors.New("profile excluded")
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
			api.projectSkills.refuseWithPolicyMode(root, "outside profile", time.Now(), true)
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
			for _, tc := range []struct {
				name    string
				input   map[string]interface{}
				linkErr error
			}{
				{"nested-file", map[string]interface{}{"skill": "sample", "skill_path": file}, nil},
				{"nested-relative-file", map[string]interface{}{"skill": "sample", "source_path": filepath.Join(".claude", "skills", "sample", "refs", "guide.md")}, nil},
				{"nested-dir", map[string]interface{}{"skill": "sample", "skill_path": refs}, nil},
				{"nested-link", map[string]interface{}{"skill": "sample", "skill_path": link}, linkErr},
				{"skill-alias-link", map[string]interface{}{"skill": "sample", "skill_path": alias}, aliasErr},
				{"manifest-alias-link", map[string]interface{}{"skill": "sample", "skill_path": manifestAlias}, manifestAliasErr},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if tc.linkErr != nil {
						t.Skipf("link unavailable: %v", tc.linkErr)
					}
					decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
						HookEventName: "PreToolUse", ToolName: "Skill", CWD: project, ToolInput: tc.input,
					})
					if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
						t.Errorf("selected protected skill descendant: %+v, matched=%v; want project-skill-unverified block", decision, matched)
					}
				})
			}
		})
	}
}

// TestReviewG621R2UnrelatedSkillWithUnreadableProjectRoot exercises a
// gateway that cannot stat an absent name under a refused project root while
// the caller selects a separate, ordinary user skill of that name.
func TestReviewG621R2UnrelatedSkillWithUnreadableProjectRoot(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	userSkill := filepath.Join(home, ".claude", "skills", "ordinary")
	if err := os.MkdirAll(userSkill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userSkill, "SKILL.md"), []byte("---\nname: ordinary\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ordinaryAliasDir := filepath.Join(project, "ordinary-alias")
	if err := os.MkdirAll(ordinaryAliasDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ordinaryAlias := filepath.Join(ordinaryAliasDir, "SKILL.md")
	ordinaryAliasErr := os.Symlink(filepath.Join(userSkill, "SKILL.md"), ordinaryAlias)
	if err := os.Chmod(root, 0); err != nil {
		t.Skipf("folder permissions unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	oldCheck := gatewaySkillPathCheck
	gatewaySkillPathCheck = func(path string) error {
		if insideHome(home, path) && !insideHome(filepath.Join(home, ".claude"), path) {
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
	api.projectSkills.refuseWithPolicyMode(root, "outside profile", time.Now(), true)
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	ctx = context.WithValue(ctx, resolvedWritesContextKey{}, map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootOutsideProfile,
	})
	check := func(input map[string]interface{}) {
		t.Helper()
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project, ToolInput: input,
		})
		if matched && decision.Action == "block" {
			t.Errorf("ordinary user skill was refused because an unrelated project root was unreadable: %+v", decision)
		}
	}
	check(map[string]interface{}{"skill": "ordinary"})
	t.Run("ordinary-alias", func(t *testing.T) {
		if ordinaryAliasErr != nil {
			t.Skipf("link unavailable: %v", ordinaryAliasErr)
		}
		check(map[string]interface{}{"skill": "ordinary", "skill_path": ordinaryAlias})
	})
}

func TestReviewG621R2SkillFolderNamedManifest(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	skill := filepath.Join(root, "SKILL.md")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
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
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	ctx = context.WithValue(ctx, resolvedWritesContextKey{}, map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootOutsideProfile,
		hookpaths.ProjectSkillSelectedPrefix + skill:      "sample",
	})
	for _, input := range []map[string]interface{}{
		{"skill": "sample"},
		{"skill": "sample", "skill_path": skill},
	} {
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project, ToolInput: input,
		})
		if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
			t.Errorf("selected protected skill folder named SKILL.md: %+v, matched=%v; want project-skill-unverified block", decision, matched)
		}
	}
}
