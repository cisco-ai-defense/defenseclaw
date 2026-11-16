// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0665: a managed Windows gateway runs as LocalSystem and does not read
// inside user profiles. A user or project skill on asset_policy.skill.denied
// typed as /name is refused there too, as the Skill tool call is, at the
// folder the hook reported or, when it reported none, by name. An allowed
// skill and an ordinary command still expand.
func TestClaudeSlashSkillDeniedWhereGatewaySkipsUserProfiles(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	userSkill := filepath.Join(home, ".claude", "skills", "fc-wm-denied")
	projectSkill := filepath.Join(project, ".claude", "skills", "fc-wm-denied")
	allowedSkill := filepath.Join(home, ".claude", "skills", "fc-wm-allowed")
	for dir, name := range map[string]string{userSkill: "fc-wm-denied", projectSkill: "fc-wm-denied", allowedSkill: "fc-wm-allowed"} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	commands := filepath.Join(project, ".claude", "commands")
	if err := os.MkdirAll(commands, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(commands, "ordinary-command.md"), []byte("Say hi.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The home stands in for the user profile the gateway refuses to read.
	previous := gatewaySkillPathCheck
	gatewaySkillPathCheck = func(path string) error {
		if rel, err := filepath.Rel(home, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New("inside a user profile")
		}
		return nil
	}
	t.Cleanup(func() { gatewaySkillPathCheck = previous })

	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Mode = "action"
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "fc-wm-denied"}}
	store, logger := newNativeSkillRuntimeTestStore(t)
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg}
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	reporting := func(dirs ...string) context.Context {
		header := http.Header{}
		header.Set(assetfacts.Header, assetfacts.Encode(assetfacts.Facts{SkillDirs: dirs}))
		return withClaimedAssetFacts(peer, header)
	}
	slash := func(ctx context.Context, source, name string) []runtimeAssetDecision {
		return api.claudeCodeSlashCommandAssetDecisions(ctx, claudeCodeHookRequest{
			HookEventName: "UserPromptExpansion", SessionID: "s-0665-" + source + "-" + name, Prompt: "/" + name,
			ExpansionType: "slash_command", CommandName: name, CommandSource: source, CWD: project,
		})
	}
	// The hook can report the folder under another spelling of the home
	// (a redirected or aliased profile path) that matches no candidate
	// (r102 GAP-0676).
	aliased := filepath.Join(filepath.Dir(home), "alias-of-home", ".claude", "skills", "fc-wm-denied")
	for _, source := range []string{"userSettings", "projectSettings", ""} {
		for label, ctx := range map[string]context.Context{
			"user skill reported":                  reporting(userSkill),
			"project skill reported":               reporting(projectSkill),
			"unreported":                           peer,
			"reported under another home spelling": reporting(aliased),
		} {
			got := slash(ctx, source, "fc-wm-denied")
			if len(got) != 1 || got[0].decision.Action != "block" {
				t.Fatalf("source %q, %s: /fc-wm-denied = %+v, want the denied skill refused", source, label, got)
			}
			if got[0].targetType != "skill" || got[0].decision.TargetName != "fc-wm-denied" {
				t.Fatalf("source %q, %s: decision names %s %q, want skill fc-wm-denied", source, label, got[0].targetType, got[0].decision.TargetName)
			}
			// The hook_decision row names the refused skill.
			if reason := assetPolicyResponseReason(got[0].decision); !strings.Contains(reason, "asset_name=fc-wm-denied") {
				t.Fatalf("source %q, %s: reason %q does not name the skill", source, label, reason)
			}
		}
		for label, ctx := range map[string]context.Context{
			"reported": reporting(allowedSkill), "unreported": peer,
			"reported under another home spelling": reporting(filepath.Join(filepath.Dir(aliased), "fc-wm-allowed")),
		} {
			for _, got := range slash(ctx, source, "fc-wm-allowed") {
				if got.decision.Action == "block" {
					t.Fatalf("source %q, %s: /fc-wm-allowed = %+v, want it to expand", source, label, got)
				}
			}
		}
		if got := slash(peer, source, "ordinary-command"); len(got) != 0 {
			t.Fatalf("source %q: /ordinary-command = %+v, want the runtime-disable lookup only", source, got)
		}
	}
}
