// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const kubernetesBatchSecretGatewayResource = "mcp://k8s/gateway-fixture"

func TestKubernetesBatchSecretCollectionExactOwnerAndProfilePosture(t *testing.T) {
	contract, ok := exactFallbackContracts[kubernetesBatchSecretCollectionRuleID]
	if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil ||
		!contract.requiresExactDetectionProof || !contract.codeOwnedDetection ||
		contract.detectionOnly || contract.alertOnly {
		t.Fatalf("exact Kubernetes owner=%+v exists=%t", contract, ok)
	}

	profiles := []struct {
		name, action, severity string
	}{
		{name: "default", action: "alert", severity: "HIGH"},
		{name: "permissive", action: "alert", severity: "HIGH"},
		{name: "strict", action: "block", severity: "CRITICAL"},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			connector := "kubernetes-batch-secret-" + profile.name
			installToolCallCorpusProfileConnector(t, connector, profile.name)
			input := kubernetesBatchSecretGatewayInput(t, []string{
				"api-token", "database-password", "signing-key",
			})
			result := EvaluateDeterministicAction(
				t.Context(), input, string(input.Args), connector, profile.name,
			)
			if !slices.Contains(result.RuleIDs, kubernetesBatchSecretCollectionRuleID) ||
				result.Action != profile.action || result.Severity != profile.severity ||
				result.EnforceableSeverity != profile.severity {
				t.Fatalf("result=%+v, want %s %s %s",
					result, kubernetesBatchSecretCollectionRuleID, profile.action, profile.severity)
			}
			findingIndex := slices.IndexFunc(result.Findings, func(finding DeterministicActionFinding) bool {
				return finding.RuleID == kubernetesBatchSecretCollectionRuleID
			})
			if findingIndex < 0 || !result.Findings[findingIndex].ContributesToEnforcement {
				t.Fatalf("exact owner did not contribute enforcement: %+v", result.Findings)
			}
		})
	}
}

func TestKubernetesBatchSecretCollectionGatewayNearMissesStayQuiet(t *testing.T) {
	tests := []struct {
		name     string
		identity string
		raw      string
	}{
		{name: "missing identity", raw: `{"cluster":"prod-cluster","namespaces":["production"],"secret_names":["one","two","three"],"decode_base64":true}`},
		{name: "two secrets", identity: kubernetesBatchSecretGatewayResource, raw: `{"cluster":"prod-cluster","namespaces":["production"],"secret_names":["one","two"],"decode_base64":true}`},
		{name: "decode disabled", identity: kubernetesBatchSecretGatewayResource, raw: `{"cluster":"prod-cluster","namespaces":["production"],"secret_names":["one","two","three"],"decode_base64":false}`},
		{name: "duplicate secret", identity: kubernetesBatchSecretGatewayResource, raw: `{"cluster":"prod-cluster","namespaces":["production"],"secret_names":["one","two","one"],"decode_base64":true}`},
		{name: "dynamic secret", identity: kubernetesBatchSecretGatewayResource, raw: `{"cluster":"prod-cluster","namespaces":["production"],"secret_names":["one","two","{{secret}}"],"decode_base64":true}`},
		{name: "unknown key", identity: kubernetesBatchSecretGatewayResource, raw: `{"cluster":"prod-cluster","namespaces":["production"],"secret_names":["one","two","three"],"decode_base64":true,"context":"admin"}`},
	}

	const profile = "strict"
	const connector = "kubernetes-batch-secret-near-misses"
	installToolCallCorpusProfileConnector(t, connector, profile)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := actionfacts.Input{
				Tool: "k8s.get_secrets_batch", Args: json.RawMessage(test.raw),
				ToolResourceIdentity: test.identity,
			}
			result := EvaluateDeterministicAction(
				t.Context(), input, string(input.Args), connector, profile,
			)
			if slices.Contains(result.RuleIDs, kubernetesBatchSecretCollectionRuleID) {
				t.Fatalf("near miss produced batch-secret finding: %+v", result)
			}
		})
	}
}

func kubernetesBatchSecretGatewayInput(t *testing.T, names []string) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"cluster": "prod-cluster-ap-south-1", "namespaces": []string{"production"},
		"secret_names": names, "decode_base64": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{
		Tool: "k8s.get_secrets_batch", Args: raw,
		ToolResourceIdentity: kubernetesBatchSecretGatewayResource,
	}
}
