// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

const adcsCertificateChainID = "chain.adcs_certificate_request_then_pfx_authentication"

func TestProjectADCSCertificateImpersonationChainRequiresResultBeforeEnforcement(t *testing.T) {
	definition, _ := guardrail.ToolChainDefinitionByID(adcsCertificateChainID)
	index, _ := guardrail.ToolChainIndexByID(adcsCertificateChainID)
	requestFacts := actionfacts.Analyze(actionfacts.Input{
		Tool: "execute_command",
		Command: "certipy-ad req -u operator@example.local -p supplied-secret" +
			" -ca EXAMPLE-CA -template ESC1 -upn administrator@example.local" +
			" -target ca.example.local -dc-ip 192.0.2.10",
	})
	request := guardrail.ToolChainProjection{ParseStatus: requestFacts.Parse.Status}
	projectTrustedActionChainSteps(&request, requestFacts, nil)
	if request.DetectionStepMask&definition.Step1Bit == 0 ||
		request.EnforcementStepMask&definition.Step1Bit != 0 ||
		request.EnforcementJoinDigests[index] != "" {
		t.Fatalf("request projection=%+v", request)
	}

	authFacts := actionfacts.Analyze(actionfacts.Input{
		Tool: "execute_command",
		Command: "certipy-ad auth -pfx administrator.pfx -dc-ip 192.0.2.10" +
			" -username administrator -domain example.local",
	})
	auth := guardrail.ToolChainProjection{ParseStatus: authFacts.Parse.Status}
	projectTrustedActionChainSteps(&auth, authFacts, nil)
	if auth.DetectionStepMask&definition.Step2Bit == 0 ||
		auth.EnforcementStepMask&definition.Step2Bit == 0 ||
		auth.EnforcementJoinDigests[index] == "" {
		t.Fatalf("auth projection=%+v", auth)
	}
}

func TestADCSCertificateImpersonationLifecyclePosture(t *testing.T) {
	for _, test := range []struct {
		posture   string
		wantBlock bool
	}{
		{posture: "default"},
		{posture: "permissive"},
		{posture: "strict", wantBlock: true},
	} {
		t.Run(test.posture, func(t *testing.T) {
			api, profile := newADCSCertificateLifecycleAPI(t, test.posture)
			const session = "adcs-positive"
			request := adcsCertificateRequestPayload(session, "request")
			runSQLLifecycleGatewayStage(t, api, profile, request)
			_, requestResult := runSQLLifecycleGatewayStage(
				t, api, profile, adcsCertificateSuccessfulResult(request, "administrator.pfx"),
			)
			assertRuleAbsent(t, requestResult, adcsCertificateChainID)

			_, auth := runSQLLifecycleGatewayStage(
				t, api, profile, adcsCertificateAuthPayload(session, "auth", "administrator.pfx"),
			)
			assertRulePresent(t, auth, adcsCertificateChainID)
			if test.wantBlock != (auth.Action == guardrailActionBlock) {
				t.Fatalf("posture=%s response=%+v", test.posture, auth)
			}
			if auth.WouldBlock {
				t.Fatalf("action-mode response unexpectedly marked would-block: %+v", auth)
			}
		})
	}
}

func TestADCSCertificateImpersonationLifecycleRejectsMissingResultAndArtifactMismatch(t *testing.T) {
	for _, test := range []struct {
		name       string
		resultPFX  string
		authPFX    string
		skipResult bool
	}{
		{name: "missing request result", authPFX: "administrator.pfx", skipResult: true},
		{name: "different artifact", resultPFX: "administrator.pfx", authPFX: "auditor.pfx"},
	} {
		t.Run(test.name, func(t *testing.T) {
			api, profile := newADCSCertificateLifecycleAPI(t, "strict")
			request := adcsCertificateRequestPayload("adcs-negative", "request")
			runSQLLifecycleGatewayStage(t, api, profile, request)
			if !test.skipResult {
				runSQLLifecycleGatewayStage(
					t, api, profile, adcsCertificateSuccessfulResult(request, test.resultPFX),
				)
			}
			_, auth := runSQLLifecycleGatewayStage(
				t, api, profile,
				adcsCertificateAuthPayload("adcs-negative", "auth", test.authPFX),
			)
			assertRuleAbsent(t, auth, adcsCertificateChainID)
			if auth.Action == guardrailActionBlock || auth.WouldBlock {
				t.Fatalf("negative blocked: %+v", auth)
			}
		})
	}
}

func newADCSCertificateLifecycleAPI(
	t *testing.T,
	posture string,
) (*APIServer, connector.HookProfile) {
	t.Helper()
	api, profile := newSQLValuePersistenceLifecycleAPI(t, "claudecode")
	api.scannerCfg.Guardrail.RulePackDir = filepath.Join(
		guardrailPoliciesRoot(t), posture,
	)
	return api, profile
}

func adcsCertificateRequestPayload(session, callID string) map[string]interface{} {
	return map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": session,
		"tool_use_id": callID, "tool_name": "execute_command",
		"tool_input": map[string]interface{}{
			"command": "certipy-ad req -u operator@example.local -p supplied-secret" +
				" -ca EXAMPLE-CA -template ESC1 -upn administrator@example.local" +
				" -target ca.example.local -dc-ip 192.0.2.10",
		},
	}
}

func adcsCertificateAuthPayload(session, callID, pfx string) map[string]interface{} {
	return map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": session,
		"tool_use_id": callID, "tool_name": "execute_command",
		"tool_input": map[string]interface{}{
			"command": "certipy-ad auth -pfx " + pfx + " -dc-ip 192.0.2.10" +
				" -username administrator -domain example.local",
		},
	}
}

func adcsCertificateSuccessfulResult(
	pre map[string]interface{},
	pfx string,
) map[string]interface{} {
	result := cloneStringAnyMap(pre)
	result["hook_event_name"] = "PostToolUse"
	result["tool_response"] = "[*] Successfully requested certificate\n" +
		"[*] Saving certificate and private key to '" + pfx + "'\n" +
		"[*] Wrote certificate and private key to '" + pfx + "'\n"
	return result
}
