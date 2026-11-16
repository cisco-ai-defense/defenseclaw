// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The calling user's hook reports a selected project skill whose SKILL.md is
// a link out of the profile (or a hard link) as an unverified root bound to
// that skill. The Skill call is refused for every way of selecting it, with
// the reason worded for the manifest, and the next call that finds the root
// ordinary retires the refusal (rel-1-0-9:GAP-0951).
func TestSelectedProjectSkillWithLinkedManifestIsRefusedAndRetired(t *testing.T) {
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
	call := func(facts map[string]string) context.Context {
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
		return context.WithValue(ctx, resolvedWritesContextKey{}, facts)
	}
	linked := call(map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root: hookpaths.ProjectSkillManifestLinked,
		hookpaths.ProjectSkillSelectedPrefix + skill:      "sample",
	})
	api.noteExcludedProjectSkillFolders(linked, "claudecode", home, project)
	if got := api.projectSkills.unverifiedFolders(); len(got) != 1 || !strings.Contains(got[0], "SKILL.md") {
		t.Fatalf("unverified folders = %v, want the root listed with the manifest reason", got)
	}
	for name, input := range map[string]map[string]interface{}{
		"name":          {"skill": "sample"},
		"folder-path":   {"skill": "sample", "skill_path": skill},
		"manifest-path": {"skill": "sample", "skill_path": manifest},
		"manifest-nest": {"skill": map[string]interface{}{"name": "sample", "path": manifest}},
	} {
		t.Run(name, func(t *testing.T) {
			decision, matched := api.claudeCodeSkillAssetDecision(linked, claudeCodeHookRequest{
				HookEventName: "PreToolUse", ToolName: "Skill", CWD: project, ToolInput: input,
			})
			if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
				t.Errorf("linked manifest selection = %+v matched=%v; want project-skill-unverified block", decision, matched)
			}
		})
	}
	// Benign twin: a later call finds the root ordinary and verified.
	api.noteExcludedProjectSkillFolders(call(map[string]string{hookpaths.ProjectSkillRootVerifiedPrefix + root: "1"}), "claudecode", home, project)
	if got := api.projectSkills.unverifiedFolders(); len(got) != 0 {
		t.Errorf("verified root remains reported unverified: %v", got)
	}
}
