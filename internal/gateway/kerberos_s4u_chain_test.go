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

const kerberosS4UChainID = "chain.s4u_ticket_then_kerberos_secretsdump_same_cache"

func TestProjectKerberosS4UChainRequiresAuthenticatedResultBeforeEnforcement(t *testing.T) {
	definition, _ := guardrail.ToolChainDefinitionByID(kerberosS4UChainID)
	index, _ := guardrail.ToolChainIndexByID(kerberosS4UChainID)
	requestFacts := actionfacts.Analyze(actionfacts.Input{
		Tool: "execute_command", Command: kerberosS4URequestCommand(),
	})
	request := guardrail.ToolChainProjection{ParseStatus: requestFacts.Parse.Status}
	projectTrustedActionChainSteps(&request, requestFacts, nil)
	if request.DetectionStepMask&definition.Step1Bit == 0 ||
		request.EnforcementStepMask&definition.Step1Bit != 0 ||
		request.EnforcementJoinDigests[index] == "" {
		t.Fatalf("request projection=%+v", request)
	}

	sinkFacts := actionfacts.Analyze(actionfacts.Input{
		Tool: "execute_command", Command: kerberosS4USecretsDumpCommand("administrator.ccache"),
	})
	sink := guardrail.ToolChainProjection{ParseStatus: sinkFacts.Parse.Status}
	projectTrustedActionChainSteps(&sink, sinkFacts, nil)
	if sink.DetectionStepMask&definition.Step2Bit == 0 ||
		sink.EnforcementStepMask&definition.Step2Bit == 0 ||
		sink.EnforcementJoinDigests[index] == "" ||
		sink.EnforcementJoinDigests[index] == request.EnforcementJoinDigests[index] {
		t.Fatalf("sink projection=%+v", sink)
	}
}

func TestKerberosS4ULifecyclePosture(t *testing.T) {
	for _, test := range []struct {
		posture   string
		wantBlock bool
	}{
		{posture: "default"},
		{posture: "permissive"},
		{posture: "strict", wantBlock: true},
	} {
		t.Run(test.posture, func(t *testing.T) {
			api, profile := newKerberosS4ULifecycleAPI(t, test.posture)
			const session = "s4u-positive"
			request := kerberosS4URequestPayload(session, "request")
			runSQLLifecycleGatewayStage(t, api, profile, request)
			_, result := runSQLLifecycleGatewayStage(
				t, api, profile,
				kerberosS4USuccessfulResult(request, "administrator", "administrator.ccache"),
			)
			assertRuleAbsent(t, result, kerberosS4UChainID)

			_, sink := runSQLLifecycleGatewayStage(
				t, api, profile,
				kerberosS4USecretsDumpPayload(session, "sink", "administrator.ccache"),
			)
			assertRulePresent(t, sink, kerberosS4UChainID)
			if test.wantBlock != (sink.Action == guardrailActionBlock) {
				t.Fatalf("posture=%s response=%+v", test.posture, sink)
			}
			if sink.WouldBlock {
				t.Fatalf("action-mode response unexpectedly marked would-block: %+v", sink)
			}
		})
	}
}

func TestKerberosS4ULifecycleRejectsIncompleteOrMismatchedLineage(t *testing.T) {
	for _, test := range []struct {
		name            string
		resultPrincipal string
		resultCache     string
		sinkCache       string
		skipResult      bool
	}{
		{name: "missing result", sinkCache: "administrator.ccache", skipResult: true},
		{name: "principal mismatch", resultPrincipal: "auditor", resultCache: "administrator.ccache", sinkCache: "administrator.ccache"},
		{name: "cache mismatch", resultPrincipal: "administrator", resultCache: "administrator.ccache", sinkCache: "auditor.ccache"},
	} {
		t.Run(test.name, func(t *testing.T) {
			api, profile := newKerberosS4ULifecycleAPI(t, "strict")
			request := kerberosS4URequestPayload("s4u-negative", "request")
			runSQLLifecycleGatewayStage(t, api, profile, request)
			if !test.skipResult {
				runSQLLifecycleGatewayStage(
					t, api, profile,
					kerberosS4USuccessfulResult(request, test.resultPrincipal, test.resultCache),
				)
			}
			_, sink := runSQLLifecycleGatewayStage(
				t, api, profile,
				kerberosS4USecretsDumpPayload("s4u-negative", "sink", test.sinkCache),
			)
			assertRuleAbsent(t, sink, kerberosS4UChainID)
			if sink.Action == guardrailActionBlock || sink.WouldBlock {
				t.Fatalf("negative blocked: %+v", sink)
			}
		})
	}
}

func newKerberosS4ULifecycleAPI(
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

func kerberosS4URequestCommand() string {
	return "impacket-getST -spn cifs/dc.lab.example -impersonate administrator " +
		"lab.example/operator:supplied-secret"
}

func kerberosS4USecretsDumpCommand(cache string) string {
	return "export KRB5CCNAME=" + cache + " && " +
		"impacket-secretsdump -k -no-pass -dc-ip 192.0.2.10 lab.example"
}

func kerberosS4URequestPayload(session, callID string) map[string]interface{} {
	return map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": session,
		"tool_use_id": callID, "tool_name": "execute_command",
		"tool_input": map[string]interface{}{"command": kerberosS4URequestCommand()},
	}
}

func kerberosS4USecretsDumpPayload(session, callID, cache string) map[string]interface{} {
	return map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": session,
		"tool_use_id": callID, "tool_name": "execute_command",
		"tool_input": map[string]interface{}{"command": kerberosS4USecretsDumpCommand(cache)},
	}
}

func kerberosS4USuccessfulResult(
	pre map[string]interface{},
	principal string,
	cache string,
) map[string]interface{} {
	result := cloneStringAnyMap(pre)
	result["hook_event_name"] = "PostToolUse"
	result["tool_response"] = "[*] Impersonating " + principal + "\n" +
		"[*] Requesting S4U2self\n" +
		"[*] Requesting S4U2Proxy\n" +
		"[*] Saving ticket in " + cache + "\n"
	return result
}
