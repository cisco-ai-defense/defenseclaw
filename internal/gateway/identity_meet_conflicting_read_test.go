// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Both assignments are proven. The action member's private-key read must
// still block when an observing member reports the same ID at higher severity.
func TestMeetConflictingReadKeepsEachMembersVerdictAndAudit(t *testing.T) {
	stubProfileSources(t)
	const keyPath = "/home/alice/.ssh/id_rsa"
	root := t.TempDir()
	profiles := map[string]config.GuardrailProfile{
		"a": {Mode: "action", BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "READ-A")},
		"b": {Mode: "observe", BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "READ-B"),
			Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{"observer.example"}}},
	}
	set, ctx := meetOfTwoAssignments(t, "action", profiles, "a", "b", "codex")
	for name, severity := range map[string]string{"a": "HIGH", "b": "CRITICAL"} {
		rule := meetVerdictRule("PATH-SSH-KEY", keyPath, severity)
		generation, err := compileRulePackGeneration([]ruleCategory{{Name: "secret", Rules: []PatternRule{*rule}}})
		if err != nil {
			t.Fatal(err)
		}
		set.rules[effectiveRulePackKey(set.profiles[name].Config, "codex")] = generation
	}
	set.missing = nil
	if decision := resolvedGuardrailProfileFrom(ctx).decision; !config.IsProfileMeet(decision.Name) || decision.Refused != "" {
		t.Fatalf("proven assignments did not select a meet: %+v", decision)
	}
	request := trustedActionRequest{
		Input: actionfacts.Input{Tool: "Read", Args: json.RawMessage(`{"path":"/home/alice/.ssh/id_rsa","file_path":"/repo/notes.txt"}`),
			CWD: "/repo", ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX},
		Connector: "codex", EnforcementCapable: true,
	}
	findings := dispatchTrustedAction(ctx, request)
	for _, member := range []string{"a", "b"} {
		count := 0
		for _, finding := range findings {
			if finding.RuleID == "PATH-SSH-KEY" && finding.profile == member {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s emitted %d private-key findings, want one: %+v", member, count, findings)
		}
	}
	if action := profileMeetActionForFindings(ctx, set.profileConfig(config.ProfileMeetName([]string{"a", "b"})), "codex", findings, true, false); action != guardrailActionBlock {
		t.Fatalf("conflicting read action = %q, want action member's block; findings=%+v", action, findings)
	}
}
