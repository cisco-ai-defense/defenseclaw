// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestSandboxOnlyUncertaintyDoesNotRefuseObserveHookOrInspect(t *testing.T) {
	stubProfileSources(t)
	p := identityTestPlatforms[0]
	subject := identityTestSubject(p, p.providers[0], stateProven, false)
	subject.holderUnproven = true
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.DefaultProfile = "watch"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"watch": {Mode: "observe"},
		"other": {Mode: "observe", Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{"blocked.example"}}},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{
		Profile: "other", Match: config.ProfileMatch{Users: []string{p.name}},
	}}
	api := &APIServer{scannerCfg: cfg}
	api.guardrailProfiles.set.Store(newGuardrailProfileSetFor(t, cfg))
	base := context.WithValue(t.Context(), testVerifiedSubjectKey{}, subject)
	for _, path := range []profilePath{profilePathHook, profilePathInspect} {
		ctx := api.withGuardrailProfileDecision(withProfilePath(base, path), "codex")
		if got := resolvedGuardrailProfileFrom(ctx).decision; got.Refused != "" {
			t.Errorf("path %d refused: %+v", path, got)
		}
		if path == profilePathHook {
			if resp, refused := api.refuseProfileHook(ctx, connector.HookProfile{}, "codex",
				agentHookRequest{ConnectorName: "codex", HookEventName: "pre_tool_use"}, nil, nil); refused {
				t.Errorf("observe hook refused: %+v", resp)
			}
		}
	}
	pathless := api.withGuardrailProfileDecision(base, "codex")
	if got := resolvedGuardrailProfileFrom(pathless).decision; got.Refused == "" {
		t.Fatalf("pathless sandbox selection disclosed an unproven profile: %+v", got)
	}
}
