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

const kubernetesPrivilegedPodRunRuleID = "privilege.kubernetes_privileged_pod_run"

func TestKubernetesPrivilegedPodRunSemanticOwnerAndCEL(t *testing.T) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticKubernetesPrivilegedPodRunExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[kubernetesPrivilegedPodRunRuleID]
	if owner.prerequisite == nil || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}
	input := actionfacts.Input{Tool: "kubectl", Args: json.RawMessage(
		`{"command":"run inspector --image=busybox --privileged --restart=Never","namespace":"production"}`,
	)}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, EnforcementCapable: true})
	matched := findingWithID(findings, kubernetesPrivilegedPodRunRuleID)
	if matched == nil || matched.Severity != "HIGH" || matched.contributesToEnforcement() ||
		!matched.contributesToAlertOnly() || matched.Evidence != "" {
		t.Fatalf("semantic finding=%+v all=%v", matched, FindingStrings(findings))
	}
}

func TestKubernetesPrivilegedPodRunAlertsWithoutBlockingInEveryProfile(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "kubectl", CWD: "/repo",
				ToolInput: map[string]interface{}{"command": "run inspector --image=busybox --privileged", "namespace": "production"},
			})
			if response.Action != guardrailActionAlert || response.RawAction != guardrailActionAlert ||
				response.Severity != "HIGH" || response.WouldBlock ||
				!findingStringHasRuleID(response.Findings, kubernetesPrivilegedPodRunRuleID) {
				t.Fatalf("profile=%s response=%+v", profile, response)
			}
		})
	}
}

func TestKubernetesPrivilegedPodRunSafeNegativesDoNotMatch(t *testing.T) {
	for _, command := range []string{
		"run inspector --image=busybox",
		"run inspector --image=busybox --privileged --dry-run=client",
		"run inspector --image=busybox -- --privileged",
	} {
		input := actionfacts.Input{Tool: "kubectl", Args: json.RawMessage(`{"command":` + podRunJSONString(command) + `}`)}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, EnforcementCapable: true})
		if findingWithID(findings, kubernetesPrivilegedPodRunRuleID) != nil {
			t.Fatalf("safe negative matched: %q", command)
		}
	}
}

func podRunJSONString(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
