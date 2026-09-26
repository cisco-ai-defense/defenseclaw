// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const (
	kubernetesNamedSecretReadRuleID          = "credential.kubernetes_named_secret_content_read"
	protectedKubernetesNamedSecretReadRuleID = "credential.protected_kubernetes_named_secret_content_read"
	pamPermitAuthenticationBypassRuleID      = "tamper.pam_permit_authentication_bypass"
	dockerInsecureHTTPRegistryRuleID         = "tamper.docker_insecure_http_registry"
)

func TestExactAdministrativeSecurityRulePosture(t *testing.T) {
	tests := []struct {
		name    string
		ruleID  string
		input   actionfacts.Input
		actions map[string]string
	}{
		{
			name:   "PAM authentication bypass",
			ruleID: pamPermitAuthenticationBypassRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/pam.d/sshd",
				"content":   "auth sufficient pam_permit.so\n",
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure HTTP registry",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"insecure-registries":["http://mirror.local"]}`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "named Kubernetes Secret content read",
			ruleID: kubernetesNamedSecretReadRuleID,
			input: actionfacts.Input{
				Tool:        "execute_command",
				Command:     "kubectl get secret database-login -n payments -o json",
				DialectHint: actionfacts.DialectPOSIX,
			},
			actions: map[string]string{"default": "alert", "permissive": "alert", "strict": "alert"},
		},
	}

	for _, test := range tests {
		for profile, wantAction := range test.actions {
			t.Run(test.name+"/"+profile, func(t *testing.T) {
				connector := "exact-admin-security-" + profile + "-" + test.ruleID
				installToolCallCorpusProfileConnector(t, connector, profile)
				result := EvaluateDeterministicAction(
					t.Context(), test.input, string(test.input.Args), connector, profile,
				)
				if !slices.Contains(result.RuleIDs, test.ruleID) || result.Action != wantAction {
					t.Fatalf("result=%+v, want %s action %s", result, test.ruleID, wantAction)
				}
			})
		}
	}
}

func TestProtectedKubernetesNamedSecretReadBlocks(t *testing.T) {
	connector := activateUseCaseProfile(t, "kubernetes-production-protection")
	input := actionfacts.Input{
		Tool:        "execute_command",
		Command:     "kubectl get secret database-login -n payments -o json",
		DialectHint: actionfacts.DialectPOSIX,
	}
	result := EvaluateDeterministicAction(
		t.Context(), input, input.Command, connector, "default",
	)
	if !slices.Contains(result.RuleIDs, protectedKubernetesNamedSecretReadRuleID) ||
		result.Action != "block" {
		t.Fatalf("result=%+v, want protected Kubernetes Secret block", result)
	}
}

func TestExactAdministrativeSecurityRuleHardNegatives(t *testing.T) {
	tests := []struct {
		name, ruleID string
		input        actionfacts.Input
	}{
		{
			name:   "PAM documentation",
			ruleID: pamPermitAuthenticationBypassRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/pam.d/README.md",
				"content":   "auth sufficient pam_permit.so\n",
			}),
		},
		{
			name:   "Docker HTTPS registry",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"insecure-registries":["https://mirror.local"]}`,
			}),
		},
		{
			name:   "Kubernetes Secret name only",
			ruleID: kubernetesNamedSecretReadRuleID,
			input: actionfacts.Input{
				Tool:        "execute_command",
				Command:     "kubectl get secret database-login -o name",
				DialectHint: actionfacts.DialectPOSIX,
			},
		},
	}

	connector := "exact-admin-security-negatives"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := EvaluateDeterministicAction(
				t.Context(), test.input, string(test.input.Args), connector, "strict",
			)
			if slices.Contains(result.RuleIDs, test.ruleID) {
				t.Fatalf("hard negative matched %s: %+v", test.ruleID, result)
			}
		})
	}
}

func TestExactAdministrativeSecurityContractsAreCodeOwned(t *testing.T) {
	for _, ruleID := range []string{
		kubernetesNamedSecretReadRuleID,
		protectedKubernetesNamedSecretReadRuleID,
		pamPermitAuthenticationBypassRuleID,
		dockerInsecureHTTPRegistryRuleID,
	} {
		contract, ok := exactFallbackContracts[ruleID]
		if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil ||
			!contract.requiresExactDetectionProof || !contract.codeOwnedDetection ||
			contract.detectionOnly {
			t.Fatalf("contract %s=%+v exists=%t", ruleID, contract, ok)
		}
	}
	if !exactFallbackContracts[kubernetesNamedSecretReadRuleID].alertOnly {
		t.Fatal("universal named Secret content read must remain alert-only")
	}
	if exactFallbackContracts[protectedKubernetesNamedSecretReadRuleID].alertOnly {
		t.Fatal("protected named Secret content read must be enforcement-capable")
	}
}

func exactStructuredInput(t *testing.T, tool string, arguments map[string]any) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: tool, Args: raw}
}
