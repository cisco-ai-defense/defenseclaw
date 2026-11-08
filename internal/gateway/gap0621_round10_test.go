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

// REVIEW-9: the caller sends a selected-folder fact when a private Skill
// folder holds a manifest that leaves the profile. The managed gateway,
// unable to read the profile, refuses the explicit folder and manifest
// spellings with that fact in action mode; the caller private-skill
// spellings carry no fact and stay allowed (TestGAP0621R9PrivateSkillAsLinkedRoot).
func TestGAP0621R10LinkedManifestSelectedFactBlocksManagedAction(t *testing.T) {
	home := t.TempDir()
	private := filepath.Join(home, ".claude", "skills", "sample")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "SKILL.md")
	if err := os.WriteFile(outside, []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(private, "SKILL.md")); err != nil {
		t.Skipf("manifest link unavailable: %v", err)
	}
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(private, root); err != nil {
		t.Skipf("root link unavailable: %v", err)
	}
	profileSkills := filepath.Join(home, ".claude", "skills")
	if err := os.Chmod(profileSkills, 0); err != nil {
		t.Skipf("profile access simulation unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(profileSkills, 0o700) })
	if _, err := filepath.EvalSymlinks(private); err == nil {
		t.Skip("gateway can resolve the private skill")
	}
	api := g621PathOnlyAPI(t, config.AssetPolicyModeAction, root)
	facts := map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootSharedWritable,
		hookpaths.ProjectSkillSelectedPrefix + root:       "sample",
	}
	for _, source := range []string{private, filepath.Join(private, "SKILL.md")} {
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
		ctx = context.WithValue(ctx, resolvedWritesContextKey{}, facts)
		got, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
			ToolInput: map[string]interface{}{"skill": "sample", "skill_path": source},
		})
		if !matched || got.Action != "block" || got.Source != "project-skill-unverified" {
			t.Errorf("linked manifest source %s allowed: matched=%v action=%s source=%s", source, matched, got.Action, got.Source)
		}
	}
}

// REVIEW-10: a plain project Skill folder whose manifest links to a folder
// outside the profile. The caller sends the selected-folder fact when an
// explicit source names that outside folder; the managed gateway refuses it.
func TestGAP0621R10PlainFolderLinkedManifestFolderManagedAction(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	folder := filepath.Join(root, "sample")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "sample")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "SKILL.md"), filepath.Join(folder, "SKILL.md")); err != nil {
		t.Skipf("manifest link unavailable: %v", err)
	}
	// The managed service account cannot read the caller profile.
	projectClaude := filepath.Dir(root)
	if err := os.Chmod(projectClaude, 0); err != nil {
		t.Skipf("profile access simulation unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(projectClaude, 0o700) })
	if _, err := os.Stat(root); err == nil {
		t.Skip("gateway can read the project skills root")
	}
	api := g621PathOnlyAPI(t, config.AssetPolicyModeAction, root)
	facts := map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillRootSharedWritable,
		hookpaths.ProjectSkillSelectedPrefix + folder:     "sample",
	}
	for _, source := range []string{outside, filepath.Join(outside, "SKILL.md")} {
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
		ctx = context.WithValue(ctx, resolvedWritesContextKey{}, facts)
		got, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
			ToolInput: map[string]interface{}{"skill": "sample", "skill_path": source},
		})
		if !matched || got.Action != "block" || got.Source != "project-skill-unverified" {
			t.Errorf("linked manifest folder source %s allowed: matched=%v action=%s source=%s", source, matched, got.Action, got.Source)
		}
	}
}
