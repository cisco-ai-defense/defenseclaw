// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

const httpCommandInjectionRuleID = "attack.http_command_injection"

func TestHTTPCommandInjectionSemanticOwnerAndCEL(t *testing.T) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticHTTPCommandInjectionExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[httpCommandInjectionRuleID]
	if owner.prerequisite == nil || owner.suppressFallback == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}
	input := httpCommandInjectionInput(t, "request-value-must-not-cross-boundary; id")
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) || !facts.Authoritative() {
		t.Fatalf("exact structured action not owned: %+v", facts)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: "structured HTTP request", EnforcementCapable: true,
	})
	matched := findingWithID(findings, httpCommandInjectionRuleID)
	if matched == nil || matched.Severity != "HIGH" || matched.contributesToEnforcement() ||
		!matched.contributesToAlertOnly() || matched.Evidence != "" {
		t.Fatalf("semantic finding=%+v all=%v", matched, FindingStrings(findings))
	}
	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "request-value-must-not-cross-boundary") {
		t.Fatalf("finding retained raw request value: %s", encoded)
	}
}

func TestHTTPCommandInjectionAlertsWithoutBlockingInEveryProfile(t *testing.T) {
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
					"path":   "/api/admin/ping",
					"query":  map[string]interface{}{"host": "localhost; id"},
				},
			})
			if response.Action != guardrailActionAlert || response.RawAction != guardrailActionAlert ||
				response.Severity != "HIGH" || response.WouldBlock ||
				!findingStringHasRuleID(response.Findings, httpCommandInjectionRuleID) {
				t.Fatalf("profile=%s response=%+v", profile, response)
			}
		})
	}
}

func TestHTTPCommandInjectionProseAndAmbiguousArgsStayQuiet(t *testing.T) {
	tests := []struct {
		name string
		args string
	}{
		{
			name: "prose",
			args: `{"method":"POST","path":"/docs","query":{},"body":{"text":"documentation about localhost; id usage"}}`,
		},
		{
			name: "dynamic command",
			args: `{"method":"GET","path":"/ping","query":{"host":"localhost; $(whoami)"}}`,
		},
		{
			name: "unknown request field",
			args: `{"method":"GET","path":"/ping","query":{"host":"localhost; id"},"timeout":1}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "http_request", Args: json.RawMessage(test.args), CWD: "/repo"}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: test.args, EnforcementCapable: true,
			})
			if findingWithID(findings, httpCommandInjectionRuleID) != nil {
				t.Fatalf("safe or ambiguous input produced finding: %v", FindingStrings(findings))
			}
		})
	}
}

func httpCommandInjectionInput(t *testing.T, value string) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(map[string]interface{}{
		"method": "GET",
		"path":   "/api/admin/ping",
		"query":  map[string]interface{}{"host": value},
	})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: "http_request", Args: raw, CWD: "/repo"}
}
