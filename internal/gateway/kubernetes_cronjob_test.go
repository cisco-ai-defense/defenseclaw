// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

const kubernetesCronJobPrivilegedPatchRuleID = "privilege.kubernetes_cronjob_privileged_patch"

func TestKubernetesCronJobPrivilegedPatchSemanticOwnerAndCEL(t *testing.T) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticKubernetesCronJobPrivilegedPatchExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[kubernetesCronJobPrivilegedPatchRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}

	input := kubernetesCronJobPrivilegedPatchInput(t)
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) {
		t.Fatalf("exact structured patch not owned: %+v", facts)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, EnforcementCapable: true,
	})
	matched := findingWithID(findings, kubernetesCronJobPrivilegedPatchRuleID)
	if matched == nil || matched.Severity != "HIGH" ||
		matched.contributesToEnforcement() || !matched.contributesToAlertOnly() ||
		matched.Evidence != "" {
		t.Fatalf("semantic finding=%+v all=%v", matched, FindingStrings(findings))
	}
}

func TestKubernetesCronJobPrivilegedPatchAlertsWithoutBlockingInEveryProfile(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
				t.Context(),
				codexHookRequest{
					HookEventName: "PreToolUse",
					ToolName:      "kubectl",
					CWD:           "/repo",
					ToolInput: map[string]interface{}{
						"command":   `patch cronjob backup -n production --type=json -p='[{"op":"add","path":"/spec/jobTemplate/spec/template/spec/containers/0/securityContext","value":{"privileged":true}}]'`,
						"namespace": "production",
					},
				},
			)
			if response.Action != guardrailActionAlert ||
				response.RawAction != guardrailActionAlert ||
				response.Severity != "HIGH" || response.WouldBlock ||
				!findingStringHasRuleID(response.Findings, kubernetesCronJobPrivilegedPatchRuleID) {
				t.Fatalf("profile=%s response=%+v", profile, response)
			}
		})
	}
}

func TestKubernetesCronJobPrivilegedPatchSafeNegativesDoNotMatch(t *testing.T) {
	for _, input := range []actionfacts.Input{
		{Tool: "kubectl", Args: json.RawMessage(`{"command":"patch cronjob backup --type=json -p='[{\"op\":\"add\",\"path\":\"/spec/jobTemplate/spec/template/spec/containers/0/securityContext\",\"value\":{\"privileged\":false}}]'","namespace":"default"}`)},
		{Tool: "kubectl", Args: json.RawMessage(`{"command":"create job exploit --from=cronjob/backup","namespace":"default"}`)},
		{Tool: "execute_command", Command: `kubectl patch cronjob backup --type=json -p='[{"op":"add","path":"/spec/jobTemplate/spec/template/spec/containers/0/securityContext","value":{"privileged":true}}]'`},
		{Tool: "shell", Command: `printf '%s\n' 'kubectl patch cronjob backup privileged true'`},
	} {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, EnforcementCapable: true,
		})
		if findingWithID(findings, kubernetesCronJobPrivilegedPatchRuleID) != nil {
			t.Fatalf("safe negative produced owner finding: %v facts=%+v", FindingStrings(findings), actionfacts.Analyze(input))
		}
	}
}

func kubernetesCronJobPrivilegedPatchInput(t *testing.T) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(map[string]string{
		"command":   `patch cronjob backup -n production --type=json -p='[{"op":"add","path":"/spec/jobTemplate/spec/template/spec/containers/0/securityContext","value":{"privileged":true}}]'`,
		"namespace": "production",
	})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: "kubectl", Args: raw, CWD: "/repo"}
}
