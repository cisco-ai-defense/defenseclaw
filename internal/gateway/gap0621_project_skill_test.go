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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestGAP0621ProfileExcludedProjectSkillRootIsReportedAndDecided(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	restore := gatewaySkillPathCheck
	gatewaySkillPathCheck = func(path string) error {
		if insideHome(home, path) {
			return errors.New("profile root excluded")
		}
		return nil
	}
	t.Cleanup(func() { gatewaySkillPathCheck = restore })
	policy := config.DefaultAssetPolicy()
	policy.Mode = config.AssetPolicyModeAction
	api := &APIServer{
		store: store, logger: logger,
		scannerCfg:    &config.Config{AssetPolicy: policy},
		projectSkills: &projectSkillRoots{}, health: NewSidecarHealth(),
	}
	api.projectSkills.start(true)
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1004, Home: home})
	ctx = context.WithValue(ctx, resolvedWritesContextKey{}, map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + root:                    hookpaths.ProjectSkillRootOutsideProfile,
		hookpaths.ProjectSkillSelectedPrefix + filepath.Join(root, "review"): "review",
	})
	api.noteExcludedProjectSkillFolders(ctx, "claudecode", home, project)
	if got := len(api.projectSkills.unverifiedFolders()); got != 1 {
		t.Fatalf("unverified roots = %d, want 1", got)
	}
	if got := api.health.Snapshot().Watcher.Details[projectSkillRootsUnverifiedDetail]; got != 1 {
		t.Fatalf("health count = %v, want 1", got)
	}
	api.noteExcludedProjectSkillFolders(ctx, "claudecode", home, project)
	if got := len(api.projectSkills.unverifiedFolders()); got != 1 {
		t.Fatalf("repeat hook count = %d, want 1", got)
	}
	if paths := api.skillSourcePaths(ctx, "claudecode", project, skillRuntimeProbe{
		Matched: true, TargetType: "skill", SkillName: "other", Surface: "hook",
	}); len(paths) != 0 {
		t.Fatalf("unrelated selected skill inherited the project refusal: %v", paths)
	}
	paths := api.skillSourcePaths(ctx, "claudecode", project, skillRuntimeProbe{
		Matched: true, TargetType: "skill", SkillName: "review", Surface: "hook",
	})
	if len(paths) != 1 || filepath.Clean(paths[0]) != filepath.Join(root, "review") {
		t.Fatalf("profile-excluded source paths = %v", paths)
	}
	decision, matched := api.projectSkillScanPending("skill", "claudecode", "hook", paths)
	if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
		t.Fatalf("action decision = %+v, matched=%v", decision, matched)
	}
	api.scannerCfg.AssetPolicy.Mode = config.AssetPolicyModeObserve
	decision, matched = api.projectSkillScanPending("skill", "claudecode", "hook", paths)
	if !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
		t.Fatalf("observe decision = %+v, matched=%v", decision, matched)
	}
	guardianRoot := filepath.Join(home, "guardian", ".claude", "skills")
	api.projectSkills.refuse(guardianRoot, "guardian admission could not complete", time.Now())
	if guarded, found := api.projectSkillScanPending("skill", "claudecode", "hook", []string{filepath.Join(guardianRoot, "review")}); !found || guarded.Action != "block" {
		t.Fatalf("guardian refusal changed in observe mode: %+v, matched=%v", guarded, found)
	}
	if api.projectSkills.registered(root) {
		t.Fatal("profile root was added to the watcher")
	}
}

func TestGAP0621OrdinaryProfileProjectSkillStaysAllowed(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(filepath.Join(root, "ordinary"), 0o700); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{projectSkills: &projectSkillRoots{}, health: NewSidecarHealth()}
	api.projectSkills.start(true)
	ctx := context.WithValue(context.Background(), resolvedWritesContextKey{}, map[string]string{
		hookpaths.ProjectSkillRootUnverifiedPrefix + filepath.Join(home, "other", ".claude", "skills"): hookpaths.ProjectSkillRootOutsideProfile,
	})
	api.noteExcludedProjectSkillFolders(ctx, "claudecode", home, project)
	if got := api.projectSkills.unverifiedFolders(); len(got) != 0 {
		t.Fatalf("ordinary root was marked unverified: %v", got)
	}
	if decision, matched := api.projectSkillScanPending("skill", "claudecode", "hook", []string{filepath.Join(root, "ordinary")}); matched {
		t.Fatalf("ordinary root decision = %+v", decision)
	}
	if got := api.health.Snapshot().Watcher.Details[projectSkillRootsUnverifiedDetail]; got != nil {
		t.Fatalf("ordinary root health count = %v", got)
	}
	if listed := strings.Join(api.projectSkills.unverifiedFolders(), ""); listed != "" {
		t.Fatalf("ordinary root listed: %s", listed)
	}
}
