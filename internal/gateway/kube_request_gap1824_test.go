// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func kubeShellInput(command string) actionfacts.Input {
	return actionfacts.Input{Tool: "execute_command", Command: command, DialectHint: actionfacts.DialectPOSIX}
}

// TestGAP1824KubernetesSecretReadShapes: a list-all Secret read, a raw
// apiserver URL and a kubectl proxy URL take the cell of the exact
// named-Secret read (alert in the built-in tiers, block under the
// protected-cluster pack). Red at the det111/engine-train-2 tip b41b5d17dc:
// each was allowed with no finding.
func TestGAP1824KubernetesSecretReadShapes(t *testing.T) {
	shapes := []string{
		"kubectl get secrets -A -o yaml",
		"kubectl get secrets -n kube-system -o json",
		"kubectl get --raw /api/v1/secrets",
		"curl $APISERVER/api/v1/secrets",
		`curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets`,
		"kubectl proxy & curl localhost:8001/api/v1/namespaces/x/secrets",
		"curl http://127.0.0.1:8001/api/v1/secrets?watch=true",
		// The 1.0.10 exact shape keeps its verdict.
		"kubectl get secret db -n payments -o json",
	}
	for _, profile := range []string{"default", "strict", "permissive"} {
		connector := "gap1824-secret-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, shape := range shapes {
			t.Run(profile+"/"+shape, func(t *testing.T) {
				input := kubeShellInput(shape)
				result := EvaluateDeterministicAction(t.Context(), input, shape, connector, profile)
				if !slices.Contains(result.RuleIDs, kubernetesNamedSecretReadRuleID) ||
					result.Action != "alert" || result.Severity != "HIGH" {
					t.Fatalf("result=%+v, want %s alert HIGH", result, kubernetesNamedSecretReadRuleID)
				}
			})
		}
	}
	connector := activateUseCaseProfile(t, "kubernetes-production-protection")
	for _, shape := range shapes {
		t.Run("protected/"+shape, func(t *testing.T) {
			input := kubeShellInput(shape)
			result := EvaluateDeterministicAction(t.Context(), input, shape, connector, "default")
			if !slices.Contains(result.RuleIDs, protectedKubernetesNamedSecretReadRuleID) ||
				result.Action != "block" {
				t.Fatalf("result=%+v, want protected Kubernetes Secret block", result)
			}
		})
	}
}

// TestGAP1824KubernetesStdinExecShapes: pods/exec with stdin takes the
// lateral.workload_exec cell (strict records it; default and permissive
// have no pattern for it, as in 1.0.10). Red at b41b5d17dc: the bundled
// -it form had no finding in strict.
func TestGAP1824KubernetesStdinExecShapes(t *testing.T) {
	const ruleID = "lateral.workload_exec"
	shapes := []string{
		"kubectl exec -i pod -- sh",
		"kubectl exec -it pod -- bash",
		"kubectl exec -ti -n x pod -- sh",
	}
	connector := "gap1824-exec-strict"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	for _, shape := range shapes {
		t.Run("strict/"+shape, func(t *testing.T) {
			input := kubeShellInput(shape)
			result := EvaluateDeterministicAction(t.Context(), input, shape, connector, "strict")
			if !slices.Contains(result.RuleIDs, ruleID) || result.Action != "allow" {
				t.Fatalf("result=%+v, want %s recorded (allow)", result, ruleID)
			}
		})
	}
	for _, profile := range []string{"default", "permissive"} {
		connector := "gap1824-exec-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, shape := range shapes {
			t.Run(profile+"/"+shape, func(t *testing.T) {
				input := kubeShellInput(shape)
				result := EvaluateDeterministicAction(t.Context(), input, shape, connector, profile)
				if len(result.RuleIDs) != 0 || result.Action != "allow" {
					t.Fatalf("result=%+v, want no finding (1.0.10 cell)", result)
				}
			})
		}
	}
}

// TestGAP1824KubernetesBenignShapesUnchanged: routine reads and
// non-apiserver URLs stay without a finding in every tier.
func TestGAP1824KubernetesBenignShapesUnchanged(t *testing.T) {
	shapes := []string{
		"kubectl get pods",
		"kubectl get pods -A -o yaml",
		"kubectl get secrets",
		"kubectl get secrets -A",
		"kubectl describe secret db",
		"kubectl logs pod",
		"curl https://example.com/api/v1/secrets",
		"curl https://example.com/api/v1/users",
		"curl http://localhost:8001/api/v1/pods",
		"curl http://localhost:8080/api/v1/secrets",
	}
	for _, profile := range []string{"default", "strict", "permissive"} {
		connector := "gap1824-benign-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, shape := range shapes {
			t.Run(profile+"/"+shape, func(t *testing.T) {
				input := kubeShellInput(shape)
				result := EvaluateDeterministicAction(t.Context(), input, shape, connector, profile)
				if len(result.RuleIDs) != 0 || result.Action != "allow" {
					t.Fatalf("result=%+v, want no finding", result)
				}
			})
		}
	}
}
