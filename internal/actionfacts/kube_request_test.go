// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func kubeShellFacts(command string) Facts {
	return Analyze(Input{Tool: "execute_command", Command: command, DialectHint: DialectPOSIX})
}

// TestKubeRequestSecretContentShapes: every way of reading Secret content
// (GAP-1824) builds a request the secret-read rule proves; the shapes that
// print no Secret data, address no apiserver or name no Secret do not.
func TestKubeRequestSecretContentShapes(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		// kubectl reads that print the objects.
		{"kubectl get secrets -A -o yaml", true},
		{"kubectl get secrets --all-namespaces -o json", true},
		{"kubectl get secrets -A -oyaml", true},
		{"kubectl -n kube-system get secret -o yaml", true},
		{"kubectl get secret db -n payments -o json", true},
		{"kubectl get secret/db secret/api -o yaml", true},
		{"kubectl get pods,secrets -A -o json", true},
		{"kubectl get secrets.v1. -A -o yaml", true},
		{"kubectl get secrets -A -o jsonpath={.items[*].data}", true},
		{"kubectl get secrets -A -o go-template-file=t.tmpl", true},
		{"kubectl get secrets -w -o yaml", true},
		{"kubectl get secrets -A -o yaml | base64 -d", true},
		{"kubectl edit secret db", true},
		{"kubectl get --raw /api/v1/secrets", true},
		{"kubectl get --raw=/api/v1/namespaces/x/secrets/db", true},
		// Unparseable Secret reads fail closed.
		{"kubectl get secrets -A -o yaml --some-future-flag", true},
		{"kubectl get secrets.example.io -A -o yaml", true},
		// HTTP to an apiserver.
		{"curl $APISERVER/api/v1/secrets", true},
		{"curl https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/api/v1/secrets", true},
		{`curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets`, true},
		{"curl --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt https://10.0.0.1/api/v1/namespaces/x/secrets", true},
		{"curl https://10.0.0.1:6443/api/v1/secrets", true},
		{"kubectl proxy & curl localhost:8001/api/v1/namespaces/x/secrets", true},
		{"kubectl proxy --port=9090 & curl http://127.0.0.1:9090/api/v1/secrets", true},
		{"curl http://localhost:8001/api/v1/namespaces/x/secrets/db", true},
		{"curl http://127.0.0.1:8001/api/v1/secrets?watch=true", true},
		{"curl http://localhost:8001/api/v1/namespaces/x/%73ecrets", true},
		{"curl http://localhost:8001/api/v1/{secrets,pods}", true},
		{"curl https://kubernetes.default.svc/api/v1/$RESOURCE", true},
		{"wget -qO- http://localhost:8001/api/v1/secrets", true},
		// Benign and out of scope: unchanged.
		{"kubectl get secrets", false},
		{"kubectl get secrets -A", false},
		{"kubectl get secrets -A -o name", false},
		{"kubectl get secret db -o jsonpath={.metadata.name}", false},
		{"kubectl describe secret db", false},
		{"kubectl get pods", false},
		{"kubectl get pods -A -o yaml", false},
		{"kubectl get configmaps -A -o yaml", false},
		{"kubectl logs pod", false},
		{"kubectl create secret generic db --from-literal=a=b", false},
		{"curl https://example.com/api/v1/secrets", false},
		{"curl https://example.com/api/v1/users", false},
		{"curl $BASE/api/v1/users", false},
		{"curl $URL", false},
		{"curl http://localhost:8001/api/v1/pods", false},
		{"curl http://localhost:8080/api/v1/secrets", false},
		{"curl -X POST -d @s.json http://localhost:8001/api/v1/namespaces/x/secrets", false},
		{"curl http://localhost:8001/healthz", false},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			facts := kubeShellFacts(test.command)
			if got := KubernetesSecretContentRequest(facts); got != test.want {
				t.Fatalf("KubernetesSecretContentRequest = %v, want %v; requests %+v",
					got, test.want, facts.KubeRequests)
			}
		})
	}
}

func TestKubeRequestStdinExecShapes(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		{"kubectl exec -i pod -- sh", true},
		{"kubectl exec -it pod -- bash", true},
		{"kubectl exec -ti -n x pod -c app -- sh", true},
		{"kubectl exec --stdin pod -- sh", true},
		{"echo id | kubectl exec -i pod -- sh", true},
		{"kubectl attach -i pod", true},
		{"kubectl cp ./tool pod:/tmp/tool", true},
		{"kubectl exec --some-future-flag pod -- sh", true},
		{"curl -X POST 'http://localhost:8001/api/v1/namespaces/x/pods/p/exec?command=sh&stdin=true'", true},
		{"kubectl exec pod -- ls", false},
		{"kubectl exec pod ls", false},
		{"kubectl exec --stdin=false pod -- sh", false},
		{"kubectl attach pod", false},
		{"kubectl cp pod:/tmp/log ./log", false},
		{"kubectl logs -f pod", false},
		{"kubectl port-forward pod 8080:80", false},
		{"curl 'http://localhost:8001/api/v1/namespaces/x/pods/p/exec?command=ls&stdin=false'", false},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			facts := kubeShellFacts(test.command)
			if got := KubernetesStdinExecRequest(facts); got != test.want {
				t.Fatalf("KubernetesStdinExecRequest = %v, want %v; requests %+v",
					got, test.want, facts.KubeRequests)
			}
		})
	}
}

// TestKubeRequestTuple pins the decomposed request for each source.
func TestKubeRequestTuple(t *testing.T) {
	tests := []struct {
		command string
		want    KubeRequestFact
	}{
		{"kubectl get secrets -A -o yaml", KubeRequestFact{
			Source: KubeSourceKubectl, Verb: KubeVerbList, Resource: "secrets",
			AllNamespaces: true, RevealsContent: true}},
		{"kubectl get secret db -n payments -o json", KubeRequestFact{
			Source: KubeSourceKubectl, Verb: KubeVerbGet, Resource: "secrets",
			Namespace: "payments", Name: "db", RevealsContent: true}},
		{"curl http://127.0.0.1:8001/api/v1/secrets?watch=1", KubeRequestFact{
			Source: KubeSourceHTTP, Verb: KubeVerbWatch, Version: "v1", Resource: "secrets",
			AllNamespaces: true}},
		{"curl http://localhost:8001/apis/apps/v1/namespaces/x/deployments/web", KubeRequestFact{
			Source: KubeSourceHTTP, Verb: KubeVerbGet, Group: "apps", Version: "v1",
			Resource: "deployments", Namespace: "x", Name: "web"}},
		{"curl -X DELETE http://localhost:8001/api/v1/namespaces/x", KubeRequestFact{
			Source: KubeSourceHTTP, Verb: KubeVerbDelete, Version: "v1",
			Resource: "namespaces", Name: "x", Namespace: "x"}},
		{"kubectl exec -it -n x pod -- bash", KubeRequestFact{
			Source: KubeSourceKubectl, Verb: KubeVerbCreate, Resource: "pods", Subresource: "exec",
			Namespace: "x", Name: "pod", Stdin: true, TTY: true, Command: true}},
		{"kubectl auth can-i --list", KubeRequestFact{
			Source: KubeSourceKubectl, Verb: KubeVerbCreate, Group: "authorization.k8s.io",
			Version: "v1", Resource: "selfsubjectaccessreviews"}},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			facts := kubeShellFacts(test.command)
			if len(facts.KubeRequests) != 1 {
				t.Fatalf("requests = %+v, want one", facts.KubeRequests)
			}
			got := facts.KubeRequests[0]
			got.CommandID = 0
			if got != test.want {
				t.Fatalf("request = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestKubeRequestStructuredKubectlTool(t *testing.T) {
	raw, err := json.Marshal(map[string]string{"command": "get secrets -A -o yaml"})
	if err != nil {
		t.Fatal(err)
	}
	input := Input{Tool: "kubectl", Args: raw}
	facts := Analyze(input)
	if !KubernetesSecretContentRequest(facts) {
		t.Fatalf("structured kubectl list-all read not proved: %+v", facts.KubeRequests)
	}
}

// TestKubeRequestBound: an over-bound request list is cut and the cut
// recorded; no request is invented, so a long list of plain reads is no
// Secret read, and a Secret read past the bound is kept (DET111 T20 review
// P2-3).
func TestKubeRequestBound(t *testing.T) {
	requests := make([]KubeRequestFact, maxKubeRequests+5)
	for index := range requests {
		requests[index] = KubeRequestFact{Source: KubeSourceKubectl, Verb: KubeVerbList, Resource: "pods"}
	}
	cut, record := boundKubeRequests(requests)
	if len(cut) != maxKubeRequests || !record.caps.Any() || record.lost {
		t.Fatalf("cut = %d, record %+v", len(cut), record)
	}
	if KubernetesSecretContentRequest(Facts{KubeRequests: cut}) {
		t.Fatal("a cut of plain pod lists must not read as a Secret read")
	}
	requests[len(requests)-1] = KubeRequestFact{Source: KubeSourceHTTP, Verb: KubeVerbList, Resource: kubernetesSecretResource}
	cut, record = boundKubeRequests(requests)
	if len(cut) != maxKubeRequests || record.lost || !KubernetesSecretContentRequest(Facts{KubeRequests: cut}) {
		t.Fatalf("a Secret read past the bound must be kept: %d, %+v", len(cut), record)
	}
}
