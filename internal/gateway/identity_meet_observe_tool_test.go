// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestObserveMemberRuleDoesNotBlockUnderTheActionMember is GAP-1708: two
// proven assignments, b-first (observe) and a-second (action), each with its
// own rule. On the Codex tool path the observe member's rule finding is
// audited with its profile but contributes at most an alert; the action
// member's rule still blocks (W25-ident clauses 2-3).
func TestObserveMemberRuleDoesNotBlockUnderTheActionMember(t *testing.T) {
	stubProfileSources(t)
	root := t.TempDir()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"b-first":  {Mode: "observe", BlockAt: "LOW", RulePackDir: meetRulePackDir(t, root, "MEET-B")},
		"a-second": {Mode: "action", BlockAt: "LOW", RulePackDir: meetRulePackDir(t, root, "MEET-A")},
	}
	p := identityTestPlatforms[0]
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "b-first", Match: config.ProfileMatch{Users: []string{p.id}}},
		{Profile: "a-second", Match: config.ProfileMatch{Groups: []string{p.group}}},
	}
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []struct{ profile, prefix string }{{"b-first", "MEET-B"}, {"a-second", "MEET-A"}} {
		for _, connector := range []string{"", "codex"} {
			set.rules[effectiveRulePackKey(set.profiles[scope.profile].Config, connector)] = meetEchoMarkerGeneration(t, scope.prefix)
		}
	}
	api := &APIServer{scannerCfg: cfg}
	api.guardrailProfiles.set.Store(set)
	ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[0], stateProven, true))
	hook := api.withGuardrailProfileDecision(withAuthenticatedHookConnector(withProfilePath(ctx, profilePathHook), "codex"), "codex")
	inspect := func(marker string) *ToolInspectVerdict {
		args, err := json.Marshal(map[string]any{"command": "echo " + marker})
		if err != nil {
			t.Fatal(err)
		}
		return api.inspectToolPolicyCtx(hook, &ToolInspectRequest{Tool: "shell", Args: args, Connector: "codex"})
	}
	observed := inspect(meetPlainMarker("MEET-B"))
	if !strings.Contains(strings.Join(observed.Findings, " "), "MEET-B-ECHO") {
		t.Fatalf("fixture: the observe member's rule did not fire: %+v", observed)
	}
	if observed.Action == guardrailActionBlock || observed.Action == guardrailActionConfirm {
		t.Errorf("the observe member's rule %s the Codex tool call: %+v", observed.Action, observed)
	}
	if acting := inspect(meetPlainMarker("MEET-A")); acting.Action != guardrailActionBlock {
		t.Errorf("the action member's rule = %+v; want block", acting)
	}
}

// meetEchoMarkerGeneration is one enforceable tool-call rule, as the live
// fixture's packs hold: echo with prefix's plain marker, CRITICAL.
func meetEchoMarkerGeneration(t *testing.T, prefix string) *compiledRulePackCategories {
	t.Helper()
	marker := meetPlainMarker(prefix)
	compiled, err := compileRulePackGeneration([]ruleCategory{{Name: "command", Rules: []PatternRule{{
		ID: prefix + "-ECHO", Title: prefix + " echo marker",
		Pattern:    regexp.MustCompile(regexp.QuoteMeta(marker)),
		Expression: "f.commands.exists(c, c.argv_complete && c.program == 'echo' && '" + marker + "' in c.argv)",
		Severity:   "CRITICAL", Confidence: 1, ToolCallOnly: true,
	}}}})
	if err != nil {
		t.Fatalf("compile %s: %v", prefix, err)
	}
	return compiled
}
