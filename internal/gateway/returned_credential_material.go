// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const returnedCredentialTelemetryRedaction = "[DefenseClaw credential material omitted]"

func redactReturnedCredentialTelemetry(value string) string {
	if actionfacts.ReturnedCredentialTelemetrySensitive([]byte(value)) {
		return returnedCredentialTelemetryRedaction
	}
	return value
}

func exactReturnedCredentialResultBytes(
	req agentHookRequest,
	outcome connector.ToolLifecycleOutcome,
) ([]byte, bool) {
	if outcome != connector.ToolLifecycleOutcomeSuccess {
		return nil, false
	}
	switch canonicalConnectorRulePackKey(req.ConnectorName) {
	case "claudecode":
		if canonicalEvent(req.HookEventName) != "posttooluse" ||
			req.Payload["tool_calls"] != nil ||
			strings.TrimSpace(payloadString(req.Payload, "error")) != "" ||
			strings.TrimSpace(payloadString(req.Payload, "error_details")) != "" {
			return nil, false
		}
		response, ok := req.Payload["tool_response"].(string)
		if !ok {
			return nil, false
		}
		return []byte(response), true
	case "opencode":
		if canonicalEvent(req.HookEventName) != "toolexecuteafter" {
			return nil, false
		}
		response, ok := req.Payload["tool_response"].(map[string]interface{})
		if !ok || response["opencode_v2_status"] != "completed" {
			return nil, false
		}
		if output, ok := response["output"].(string); ok {
			return []byte(output), true
		}
		// V2's native shell result nests its text and exit status under
		// output. MCP/read tools may instead return a text content block.
		if output, ok := response["output"].(map[string]interface{}); ok {
			if text, ok := output["output"].(string); ok {
				return []byte(text), true
			}
		}
		if content, ok := response["content"].([]interface{}); ok && len(content) == 1 {
			if block, ok := content[0].(map[string]interface{}); ok && block["type"] == "text" {
				if text, ok := block["text"].(string); ok {
					return []byte(text), true
				}
			}
		}
		return nil, false
	case "amp":
		if canonicalEvent(req.HookEventName) != "toolresult" ||
			strings.TrimSpace(payloadString(req.Payload, "error")) != "" ||
			payloadString(req.Payload, "status") != "done" {
			return nil, false
		}
		response, ok := req.Payload["tool_response"].(string)
		if !ok {
			return nil, false
		}
		return []byte(response), true
	case "codex":
		// Codex shell PostToolUse does not prove success. Reuse the exact MCP
		// CallToolResult parser; it rejects scalar shell/generic responses.
		return exactSuccessfulSQLResultBytes(req)
	default:
		return nil, false
	}
}

func returnedCredentialMaterialFindings(
	source actionfacts.ReturnedCredentialSource,
	material actionfacts.ReturnedCredentialMaterial,
) []RuleFinding {
	if !actionfacts.MatchesReturnedCredentialMaterial(source, material) {
		return nil
	}
	var findings []RuleFinding
	appendFinding := func(ruleID, title, severity string, confidence float64, tags ...string) {
		findings = append(findings, RuleFinding{
			RuleID: ruleID, Title: title, Severity: severity, Confidence: confidence,
			Tags:        append(tags, "result-backed", "detection-only"),
			enforcement: findingEnforcementDetectionOnly,
			disposition: findingDispositionAdvisory,
		})
	}
	switch source {
	case actionfacts.ReturnedCredentialSourceKerberoast:
		appendFinding("credential.returned_kerberos_tgs",
			"Credential-acquisition result returned a Kerberos service ticket",
			"HIGH", 0.99, "credential", "credential-dumping")
	case actionfacts.ReturnedCredentialSourceASREPRoast:
		appendFinding("credential.returned_kerberos_asrep",
			"Credential-acquisition result returned a Kerberos AS-REP record",
			"HIGH", 0.99, "credential", "credential-dumping")
	case actionfacts.ReturnedCredentialSourceSecretsDump:
		appendFinding("credential.returned_directory_hash",
			"Credential-acquisition result returned a directory credential record",
			"HIGH", 0.99, "credential", "credential-dumping")
	case actionfacts.ReturnedCredentialSourceFileRead:
		if material&actionfacts.ReturnedCredentialKerberosTGS != 0 {
			appendFinding("credential.returned_kerberos_tgs",
				"File read returned Kerberos service-ticket material",
				"MEDIUM", 0.90, "credential", "sensitive-material")
		}
		if material&actionfacts.ReturnedCredentialKerberosASREP != 0 {
			appendFinding("credential.returned_kerberos_asrep",
				"File read returned Kerberos AS-REP material",
				"MEDIUM", 0.90, "credential", "sensitive-material")
		}
		if material&(actionfacts.ReturnedCredentialNTDSRecord|actionfacts.ReturnedCredentialLabeledNTLM) != 0 {
			appendFinding("credential.returned_directory_hash",
				"File read returned directory credential material",
				"MEDIUM", 0.90, "credential", "sensitive-material")
		}
	default:
		return nil
	}
	return findings
}
