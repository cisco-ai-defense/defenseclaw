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

func TestReviewG621SelectedProjectSkillPathForms(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	skill := filepath.Join(root, "sample")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(skill, "SKILL.md")
	if err := os.WriteFile(manifest, []byte("---\nname: sample\n---\n"), 0o600); err != nil {
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
	facts := map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootOutsideProfile,
		hookpaths.ProjectSkillSelectedPrefix + skill:      "sample",
	}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	ctx = context.WithValue(ctx, resolvedWritesContextKey{}, facts)
	api.noteExcludedProjectSkillFolders(ctx, "claudecode", home, project)
	for _, tc := range []struct {
		name  string
		input map[string]interface{}
	}{
		{"name", map[string]interface{}{"skill": "sample"}},
		{"folder-path", map[string]interface{}{"skill": "sample", "skill_path": skill}},
		{"relative-folder-path", map[string]interface{}{"skill": "sample", "skill_path": filepath.Join(".claude", "skills", "sample")}},
		{"manifest-path", map[string]interface{}{"skill": "sample", "skill_path": manifest}},
		{"manifest-path-camel", map[string]interface{}{"skill": "sample", "skillPath": manifest}},
		{"manifest-source-path", map[string]interface{}{"skill": "sample", "source_path": manifest}},
		{"manifest-nested", map[string]interface{}{"skill": map[string]interface{}{"name": "sample", "path": manifest}}},
		{"manifest-value", map[string]interface{}{"skill": manifest}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", ToolName: "Skill", CWD: project, ToolInput: tc.input,
			})
			if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
				t.Errorf("protected skill selection = %+v matched=%v; want project-skill-unverified block", decision, matched)
			}
		})
	}
}

func TestReviewG621RepairedProfileRootClearsRefusal(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	skill := filepath.Join(root, "sample")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := config.DefaultAssetPolicy()
	policy.Mode = config.AssetPolicyModeAction
	api := &APIServer{scannerCfg: &config.Config{AssetPolicy: policy}, projectSkills: &projectSkillRoots{}}
	api.projectSkills.start(true)
	unsafe := context.WithValue(context.Background(), resolvedWritesContextKey{}, map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootOutsideProfile,
	})
	api.noteExcludedProjectSkillFolders(unsafe, "claudecode", home, project)
	if decision, matched := api.projectSkillScanPending("skill", "claudecode", "hook", []string{skill}); !matched || decision.Action != "block" {
		t.Fatalf("adverse root was not blocked first: %+v matched=%v", decision, matched)
	}
	// Advance the stored finding beyond the guardian retry window without sleeping.
	api.projectSkills.refuseWithPolicyMode(root, "the project skill folder resolves outside the caller's profile", time.Now().Add(-3*projectSkillRootRetry), true)
	// A later caller-side inspection found the repaired ordinary profile root safe.
	safe := context.WithValue(context.Background(), resolvedWritesContextKey{}, map[string]string{})
	api.noteExcludedProjectSkillFolders(safe, "claudecode", home, project)
	decision, matched := api.projectSkillScanPending("skill", "claudecode", "hook", []string{skill})
	if matched && decision.Action == "block" {
		t.Errorf("repaired ordinary profile skill remains blocked: %+v", decision)
	}
	if got := api.projectSkills.unverifiedFolders(); len(got) != 0 {
		t.Errorf("repaired root remains reported unverified: %v", got)
	}
}

func TestReviewG621CodexSelectedProjectSkillUsesRecordedRoot(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".agents", "skills")
	skill := filepath.Join(root, "sample")
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
	// SessionStart reports adverse roots for Codex; Codex selects skills in a prompt.
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	ctx = context.WithValue(ctx, resolvedWritesContextKey{}, map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootOutsideProfile,
	})
	api.noteExcludedProjectSkillFolders(ctx, "codex", home, project)
	decision, matched := api.codexPromptSkillAssetDecision(ctx, codexHookRequest{
		HookEventName: "UserPromptSubmit", SessionID: "r-g621", Prompt: "$sample Use it.", CWD: project,
	})
	if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
		t.Errorf("Codex protected project skill = %+v matched=%v; want block", decision, matched)
	}
}

func TestReviewG621PinnedActionModeKeepsProjectRefusal(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	skill := filepath.Join(root, "sample")
	if err := os.MkdirAll(skill, 0o700); err != nil {
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
	live := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	live.AssetPolicy.Mode = config.AssetPolicyModeObserve
	pinned := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	pinned.AssetPolicy.Mode = config.AssetPolicyModeAction
	store, logger := newNativeSkillRuntimeTestStore(t)
	api := &APIServer{scannerCfg: live, store: store, logger: logger, projectSkills: &projectSkillRoots{}}
	api.projectSkills.start(true)
	api.projectSkills.refuseWithPolicyMode(root, "outside profile", time.Now(), true)
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	ctx = withPinnedGeneration(ctx, &Generation{N: 1, Config: pinned})
	decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
		ToolInput: map[string]interface{}{"skill": "sample", "skill_path": skill},
	})
	if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
		t.Errorf("pinned action request with newer live observe = %+v matched=%v; want block", decision, matched)
	}
}

func TestReviewG621GuardianRefusalRemainsClosed(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	store, logger := newNativeSkillRuntimeTestStore(t)
	api := &APIServer{scannerCfg: &config.Config{AssetPolicy: config.DefaultAssetPolicy()}, store: store, logger: logger, projectSkills: &projectSkillRoots{}}
	api.projectSkills.start(true)
	api.projectSkills.refuse(root, "guardian admission failed", time.Now())
	if before, matched := api.projectSkillScanPending("skill", "claudecode", "hook", []string{filepath.Join(root, "sample")}); !matched || before.Action != "block" {
		t.Fatalf("preexisting guardian refusal = %+v matched=%v; want block", before, matched)
	}
	ctx := context.WithValue(context.Background(), resolvedWritesContextKey{}, map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootOutsideProfile,
	})
	api.noteExcludedProjectSkillFolders(ctx, "claudecode", home, project)
	decision, matched := api.projectSkillScanPending("skill", "claudecode", "hook", []string{filepath.Join(root, "sample")})
	if !matched || decision.Action != "block" {
		t.Errorf("guardian refusal after later hook fact = %+v matched=%v; want block", decision, matched)
	}
}

func TestGAP0621FreshCallerInspectionRetiresOnlyCallerFinding(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	oldCheck := gatewaySkillPathCheck
	gatewaySkillPathCheck = func(string) error { return errors.New("profile excluded") }
	t.Cleanup(func() { gatewaySkillPathCheck = oldCheck })
	api := &APIServer{projectSkills: &projectSkillRoots{}, health: NewSidecarHealth()}
	api.projectSkills.start(true)
	withFacts := func(facts map[string]string) context.Context {
		return context.WithValue(context.Background(), resolvedWritesContextKey{}, facts)
	}
	api.noteExcludedProjectSkillFolders(withFacts(map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootOutsideProfile,
	}), "claudecode", home, project)
	if len(api.projectSkills.unverifiedFolders()) != 1 {
		t.Fatal("adverse caller finding was not recorded")
	}
	api.noteExcludedProjectSkillFolders(withFacts(nil), "claudecode", home, project)
	if len(api.projectSkills.unverifiedFolders()) != 1 {
		t.Fatal("missing inspection retired a finding")
	}
	api.noteExcludedProjectSkillFolders(withFacts(map[string]string{
		hookpaths.ProjectSkillRootVerifiedPrefix + root: "1",
	}), "claudecode", home, project)
	if roots, count := api.projectSkills.unverifiedFolders(), api.health.Snapshot().Watcher.Details[projectSkillRootsUnverifiedDetail]; len(roots) != 0 || count != nil {
		t.Fatalf("verified ordinary root remained refused: %v, health %v", roots, count)
	}
	api.projectSkills.refuse(root, "guardian admission failed", time.Now())
	api.noteExcludedProjectSkillFolders(withFacts(map[string]string{
		hookpaths.ProjectSkillRootVerifiedPrefix + root: "1",
	}), "claudecode", home, project)
	if len(api.projectSkills.unverifiedFolders()) != 1 {
		t.Fatal("caller inspection retired a guardian refusal")
	}
}
