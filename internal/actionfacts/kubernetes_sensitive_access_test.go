// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestKubernetesClusterWideSecretEnumerationExactSchemas(t *testing.T) {
	for _, input := range []Input{
		{Tool: "kubectl", Args: json.RawMessage(`{"command":"get secrets --all-namespaces"}`)},
		{Tool: "kubectl", Args: json.RawMessage(`{"command":"get secret -A -o json --field-selector metadata.name=fixture"}`)},
		{Tool: "kubectl", Args: json.RawMessage(`{"command":"get secrets --all-namespaces --token=fixture-token -o yaml","namespace":"default"}`)},
		{Tool: "execute_command", Args: json.RawMessage(`{"command":"kubectl get secrets --all-namespaces"}`)},
	} {
		facts := Analyze(input)
		fact, ok := ExactKubernetesSensitiveAccess(facts)
		if !ok || fact.Resource != "secrets" || !fact.AllNamespaces {
			t.Fatalf("input=%s fact=%+v facts=%+v", input.Args, fact, facts.KubernetesSensitiveAccesses)
		}
	}

	withToken := Analyze(Input{Tool: "kubectl", Args: json.RawMessage(
		`{"command":"get secrets --all-namespaces --token fixture-token"}`,
	)})
	fact, ok := ExactKubernetesSensitiveAccess(withToken)
	if !ok || !fact.TokenProvided {
		t.Fatalf("token fact=%+v ok=%t", fact, ok)
	}
}

func TestKubernetesClusterWideSecretEnumerationHardNegatives(t *testing.T) {
	for _, command := range []string{
		"get secrets -n default",
		"get secret fixture --all-namespaces",
		"auth can-i get secrets --all-namespaces",
		"get configmaps --all-namespaces",
		"get secrets --all-namespaces=false",
		"get secrets --all-namespaces --token $TOKEN",
		"get secrets --all-namespaces --output custom-columns=NAME:.metadata.name",
		"get secrets --all-namespaces --unknown value",
		"get secrets --all-namespaces --all-namespaces",
	} {
		raw, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		facts := Analyze(Input{Tool: "kubectl", Args: raw})
		if fact, ok := ExactKubernetesSensitiveAccess(facts); ok {
			t.Fatalf("hard negative %q projected %+v", command, fact)
		}
	}

	compound := Analyze(Input{Tool: "execute_command", Args: json.RawMessage(
		`{"command":"echo checking && kubectl get secrets --all-namespaces"}`,
	)})
	if _, ok := ExactKubernetesSensitiveAccess(compound); ok {
		t.Fatal("compound shell command projected as direct enumeration")
	}
}

func TestKubernetesWorkloadIdentityTokenRead(t *testing.T) {
	for _, raw := range []string{
		`{"command":"exec app-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token","namespace":"production"}`,
		`{"command":"exec app-pod -n production -- cat /var/run/secrets/kubernetes.io/serviceaccount/token","namespace":"production"}`,
		`{"command":"exec -n kube-system coredns-abc -- cat /var/run/secrets/kubernetes.io/serviceaccount/token"}`,
		`{"command":"exec app-pod -n production -- cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token"}`,
	} {
		facts := Analyze(Input{Tool: "kubectl", Args: json.RawMessage(raw)})
		if !ExactKubernetesWorkloadIdentityTokenRead(facts) {
			t.Fatalf("input=%s did not produce exact workload token read: %+v", raw, facts)
		}
	}
	conflicting := Analyze(Input{Tool: "kubectl", Args: json.RawMessage(
		`{"command":"exec app-pod -n staging -- cat /var/run/secrets/kubernetes.io/serviceaccount/token","namespace":"production"}`,
	)})
	if ExactKubernetesWorkloadIdentityTokenRead(conflicting) {
		t.Fatalf("conflicting namespace identities produced proof: %+v", conflicting)
	}
	for _, command := range []string{
		`exec app-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/namespace`,
		`exec app-pod -- sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token'`,
		`exec app-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token extra`,
		`exec $POD -- cat /var/run/secrets/kubernetes.io/serviceaccount/token`,
		`get pods --all-namespaces`,
	} {
		raw, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		facts := Analyze(Input{Tool: "kubectl", Args: raw})
		if ExactKubernetesWorkloadIdentityTokenRead(facts) {
			t.Fatalf("near miss %q produced workload token proof: %+v", command, facts)
		}
	}
}
