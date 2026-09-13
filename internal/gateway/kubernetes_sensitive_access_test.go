// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

func TestKubernetesClusterWideSecretEnumerationSemanticOwner(t *testing.T) {
	const ruleID = "secrets.kubernetes_cluster_wide_enumeration"
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticKubernetesClusterWideSecretEnumerationExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[ruleID]
	if owner.prerequisite == nil || !owner.alertOnly || owner.detectionOnly {
		t.Fatalf("owner posture=%+v", owner)
	}

	input := actionfacts.Input{Tool: "kubectl", Args: json.RawMessage(
		`{"command":"get secrets --all-namespaces -o json"}`,
	)}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: string(input.Args), EnforcementCapable: true,
	})
	match := findingWithID(findings, ruleID)
	if match == nil || match.Severity != "HIGH" || match.contributesToEnforcement() ||
		!match.contributesToAlertOnly() || match.Evidence != "" {
		t.Fatalf("finding=%+v all=%v", match, FindingStrings(findings))
	}

	safe := actionfacts.Input{Tool: "kubectl", Args: json.RawMessage(
		`{"command":"auth can-i get secrets --all-namespaces"}`,
	)}
	if got := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: safe, LegacyText: string(safe.Args), EnforcementCapable: true,
	}); findingWithID(got, ruleID) != nil {
		t.Fatalf("authorization check alerted: %v", FindingStrings(got))
	}
}

func TestKubernetesWorkloadIdentityTokenReadSemanticOwner(t *testing.T) {
	const ruleID = "secrets.kubernetes_workload_identity_token_read"
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticKubernetesWorkloadIdentityTokenReadExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[ruleID]
	if owner.prerequisite == nil || !owner.alertOnly || owner.detectionOnly {
		t.Fatalf("owner posture=%+v", owner)
	}

	input := actionfacts.Input{Tool: "kubectl", Args: json.RawMessage(
		`{"command":"exec app-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token","namespace":"production"}`,
	)}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: string(input.Args), EnforcementCapable: true,
	})
	match := findingWithID(findings, ruleID)
	if match == nil || match.Severity != "HIGH" || match.contributesToEnforcement() ||
		!match.contributesToAlertOnly() || match.Evidence != "" {
		t.Fatalf("finding=%+v all=%v", match, FindingStrings(findings))
	}

	for _, command := range []string{
		`exec app-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/namespace`,
		`exec app-pod -- sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token'`,
	} {
		raw, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		safe := actionfacts.Input{Tool: "kubectl", Args: raw}
		if got := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: safe, LegacyText: string(safe.Args), EnforcementCapable: true,
		}); findingWithID(got, ruleID) != nil {
			t.Fatalf("near miss %q alerted: %v", command, FindingStrings(got))
		}
	}
}
