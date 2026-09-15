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

const httpSQLInjectionRuleID = "attack.http_sql_injection"

func TestHTTPSQLInjectionSemanticOwnerAndCEL(t *testing.T) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticHTTPSQLInjectionExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[httpSQLInjectionRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}
	input := httpSQLInjectionInput(t)
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) || !facts.Authoritative() {
		t.Fatalf("exact structured action not owned: %+v", facts)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, EnforcementCapable: true,
	})
	matched := findingWithID(findings, httpSQLInjectionRuleID)
	if matched == nil || matched.Severity != "HIGH" || matched.contributesToEnforcement() ||
		!matched.contributesToAlertOnly() || matched.Evidence != "" {
		t.Fatalf("semantic finding=%+v all=%v", matched, FindingStrings(findings))
	}
}

func TestHTTPSQLInjectionAlertsWithoutBlockingInEveryProfile(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse",
				ToolName:      "http_request",
				CWD:           "/repo",
				ToolInput: map[string]interface{}{
					"method": "GET",
					"url":    "https://app.invalid/login?user=admin' OR '1'='1",
				},
			})
			if response.Action != guardrailActionAlert || response.RawAction != guardrailActionAlert ||
				response.Severity != "HIGH" || response.WouldBlock ||
				!findingStringHasRuleID(response.Findings, httpSQLInjectionRuleID) {
				t.Fatalf("profile=%s response=%+v", profile, response)
			}
		})
	}
}

func TestHTTPSQLInjectionProseDoesNotUseRegexFallback(t *testing.T) {
	input := actionfacts.Input{
		Tool: "http_request",
		Args: json.RawMessage(
			`{"method":"POST","url":"https://app.invalid/docs","headers":{"Content-Type":"application/json"},"body":"{\"text\":\"documentation about UNION SELECT syntax\"}"}`,
		),
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: "documentation about UNION SELECT syntax", EnforcementCapable: true,
	})
	if findingWithID(findings, httpSQLInjectionRuleID) != nil {
		t.Fatalf("prose produced finding: %v", FindingStrings(findings))
	}
}

func httpSQLInjectionInput(t *testing.T) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(map[string]interface{}{
		"method": "GET",
		"url":    "https://app.invalid/login?user=admin' OR '1'='1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: "http_request", Args: raw, CWD: "/repo"}
}
