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
)

// This test uses the pre-existing project root and skill decision APIs, so
// it can run against the 1.0.9 base as well as the fix.
func TestGAP0621ProfileExcludedRootRefusalReachesSkillDecision(t *testing.T) {
	home := t.TempDir()
	linkedProject := filepath.Join(home, "linked")
	linkedRoot := filepath.Join(linkedProject, ".claude", "skills")
	plainProject := filepath.Join(home, "plain")
	plainRoot := filepath.Join(plainProject, ".claude", "skills")
	for _, root := range []string{linkedRoot, plainRoot} {
		if err := os.MkdirAll(filepath.Join(root, "sample"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	restore := gatewaySkillPathCheck
	gatewaySkillPathCheck = func(path string) error {
		if insideHome(home, path) {
			return errors.New("profile root excluded")
		}
		return nil
	}
	t.Cleanup(func() { gatewaySkillPathCheck = restore })
	store, logger := newNativeSkillRuntimeTestStore(t)
	policy := config.DefaultAssetPolicy()
	policy.Mode = config.AssetPolicyModeAction
	roots := &projectSkillRoots{}
	roots.start(true)
	roots.refuse(linkedRoot, "project skill root is unverified", time.Now())
	api := &APIServer{scannerCfg: &config.Config{AssetPolicy: policy}, store: store, logger: logger, projectSkills: roots}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	call := func(project string) (config.AssetPolicyDecision, bool) {
		root := filepath.Join(project, ".claude", "skills")
		return api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
			ToolInput: map[string]interface{}{"skill": "sample", "skill_path": filepath.Join(root, "sample")},
		})
	}
	if decision, matched := call(linkedProject); !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
		t.Fatalf("unverified profile root = %+v, matched=%v", decision, matched)
	}
	if decision, matched := call(plainProject); matched && decision.Action == "block" {
		t.Fatalf("ordinary profile root was blocked: %+v", decision)
	}
}
