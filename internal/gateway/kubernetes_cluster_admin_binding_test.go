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

const kubernetesClusterAdminBindingRuleID = "privilege.kubernetes_cluster_admin_binding"

func TestKubernetesClusterAdminBindingSemanticOwnerAndCEL(t *testing.T) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticKubernetesClusterAdminBindingExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[kubernetesClusterAdminBindingRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}
	input := kubernetesClusterAdminBindingInput(t,
		"create clusterrolebinding persistence-binding --clusterrole=cluster-admin --serviceaccount=default:persistence-sa",
	)
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) || !facts.Authoritative() {
		t.Fatalf("exact cluster-admin binding not owned: %+v", facts)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, EnforcementCapable: true})
	matched := findingWithID(findings, kubernetesClusterAdminBindingRuleID)
	if matched == nil || matched.Severity != "HIGH" ||
		matched.contributesToEnforcement() || !matched.contributesToAlertOnly() ||
		matched.Evidence != "" {
		t.Fatalf("semantic finding=%+v all=%v", matched, FindingStrings(findings))
	}
}

func TestKubernetesClusterAdminBindingAlertsWithoutBlockingInEveryProfile(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
				t.Context(), codexHookRequest{
					HookEventName: "PreToolUse", ToolName: "kubectl", CWD: "/repo",
					ToolInput: map[string]interface{}{
						"command": "create rolebinding escalation --clusterrole=cluster-admin --serviceaccount=payments:default -n payments",
					},
				},
			)
			if response.Action != guardrailActionAlert || response.WouldBlock ||
				response.Severity != "HIGH" ||
				!findingStringHasRuleID(response.Findings, kubernetesClusterAdminBindingRuleID) {
				t.Fatalf("profile=%s response=%+v", profile, response)
			}
		})
	}
}

func TestKubernetesClusterAdminBindingSafeNegativesDoNotAlert(t *testing.T) {
	for _, command := range []string{
		"get clusterrolebinding cluster-admin -o yaml",
		"create clusterrolebinding readers --clusterrole=view --serviceaccount=default:reader",
		"create clusterrolebinding dynamic --clusterrole=cluster-admin --serviceaccount=$NS:reader",
		"create clusterrolebinding augmented --clusterrole=cluster-admin --serviceaccount=default:reader --future=true",
	} {
		input := kubernetesClusterAdminBindingInput(t, command)
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: command, EnforcementCapable: true,
		})
		if findingWithID(findings, kubernetesClusterAdminBindingRuleID) != nil {
			t.Fatalf("command=%q produced owner finding: %v", command, FindingStrings(findings))
		}
	}
}

func kubernetesClusterAdminBindingInput(t *testing.T, command string) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: "kubectl", Args: raw, CWD: "/repo"}
}
