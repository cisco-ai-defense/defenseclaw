// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

const privilegedPodManifestFixture = `apiVersion: v1
kind: Pod
metadata:
  name: host-inspection
  namespace: fixture
spec:
  containers:
  - name: inspector
    image: busybox
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
  restartPolicy: Never
`

func TestPrivilegedKubernetesOperationsAreExactAndValueFree(t *testing.T) {
	writeArgs, err := json.Marshal(map[string]string{
		"path": "/tmp/host-inspection.yaml", "content": privilegedPodManifestFixture,
	})
	if err != nil {
		t.Fatal(err)
	}
	write := Analyze(Input{Tool: "file_write", Args: writeArgs, CWD: "/repo"})
	apply := Analyze(Input{Tool: "kubectl", Args: json.RawMessage(
		`{"command":"apply -f /tmp/host-inspection.yaml"}`,
	)})
	exec := Analyze(Input{Tool: "kubectl", Args: json.RawMessage(
		`{"command":"exec -it host-inspection -n fixture -- ls /host"}`,
	)})

	writeFact, writeOK := ExactPrivilegedKubernetesOperation(write)
	applyFact, applyOK := ExactPrivilegedKubernetesOperation(apply)
	execFact, execOK := ExactPrivilegedKubernetesOperation(exec)
	if !writeOK || !applyOK || !execOK {
		t.Fatalf("operations write/apply/exec=%+v/%+v/%+v", write, apply, exec)
	}
	if writeFact.Operation != KubernetesPrivilegedManifestWrite ||
		applyFact.Operation != KubernetesManifestApply ||
		execFact.Operation != KubernetesPodHostPathExec {
		t.Fatalf("operations=%+v/%+v/%+v", writeFact, applyFact, execFact)
	}
	if writeFact.ArtifactIdentityDigest != applyFact.ArtifactIdentityDigest ||
		writeFact.PodIdentityDigest != execFact.PodIdentityDigest {
		t.Fatalf("identity joins=%+v/%+v/%+v", writeFact, applyFact, execFact)
	}
	for _, fact := range []PrivilegedKubernetesOperationFact{writeFact, applyFact, execFact} {
		if fact.ArtifactIdentityDigest == "/tmp/host-inspection.yaml" ||
			fact.PodIdentityDigest == "host-inspection" ||
			fact.PodIdentityDigest == "fixture" {
			t.Fatalf("raw identity escaped private projection: %+v", fact)
		}
	}
}

func TestPrivilegedKubernetesHardNegatives(t *testing.T) {
	manifestWithoutPrivilege := `apiVersion: v1
kind: Pod
metadata:
  name: host-inspection
spec:
  containers:
  - name: inspector
    securityContext:
      privileged: false
  volumes:
  - name: host-root
    hostPath:
      path: /
`
	manifestWithoutHostRoot := `apiVersion: v1
kind: Pod
metadata:
  name: host-inspection
spec:
  containers:
  - name: inspector
    securityContext:
      privileged: true
  volumes:
  - name: scratch
    hostPath:
      path: /tmp
`
	manifestWithUnlinkedHostRoot := `apiVersion: v1
kind: Pod
metadata:
  name: host-inspection
spec:
  containers:
  - name: inspector
    securityContext:
      privileged: true
    volumeMounts:
    - name: scratch
      mountPath: /host
  volumes:
  - name: root
    hostPath:
      path: /
`
	manifestWithUnknownField := privilegedPodManifestFixture + "  serviceAccountName: default\n"
	manifestWithAlias := `apiVersion: v1
kind: Pod
metadata:
  name: host-inspection
spec:
  containers:
  - name: inspector
    securityContext: &privileged
      privileged: true
  volumes:
  - name: root
    hostPath:
      path: /
`
	structuredWrite := func(path, content string) Input {
		raw, err := json.Marshal(map[string]string{"path": path, "content": content})
		if err != nil {
			t.Fatal(err)
		}
		return Input{Tool: "file_write", Args: raw, CWD: "/repo"}
	}
	tests := []struct {
		name  string
		input Input
	}{
		{name: "missing privileged", input: structuredWrite("/tmp/pod.yaml", manifestWithoutPrivilege)},
		{name: "missing host root", input: structuredWrite("/tmp/pod.yaml", manifestWithoutHostRoot)},
		{name: "unlinked host root", input: structuredWrite("/tmp/pod.yaml", manifestWithUnlinkedHostRoot)},
		{name: "unknown manifest field", input: structuredWrite("/tmp/pod.yaml", manifestWithUnknownField)},
		{name: "manifest anchor", input: structuredWrite("/tmp/pod.yaml", manifestWithAlias)},
		{name: "dynamic manifest path", input: structuredWrite("/tmp/${NAME}.yaml", privilegedPodManifestFixture)},
		{name: "apply namespace override", input: Input{Tool: "kubectl", Args: json.RawMessage(`{"command":"apply -n other -f /tmp/host-inspection.yaml"}`)}},
		{name: "apply stdin", input: Input{Tool: "kubectl", Args: json.RawMessage(`{"command":"apply -f -"}`)}},
		{name: "exec wrong path", input: Input{Tool: "kubectl", Args: json.RawMessage(`{"command":"exec host-inspection -n fixture -- ls /tmp"}`)}},
		{name: "exec nested shell", input: Input{Tool: "kubectl", Args: json.RawMessage(`{"command":"exec host-inspection -n fixture -- sh -c 'ls /host'"}`)}},
		{name: "exec busybox shell", input: Input{Tool: "kubectl", Args: json.RawMessage(`{"command":"exec host-inspection -n fixture -- busybox sh -c 'ls' /host"}`)}},
		{name: "dynamic pod", input: Input{Tool: "execute_command", Command: `kubectl exec "$POD" -n fixture -- ls /host`}},
		{name: "pipeline", input: Input{Tool: "execute_command", Command: `kubectl exec host-inspection -n fixture -- ls /host | head`}},
		{name: "unknown kubectl field", input: Input{Tool: "kubectl", Args: json.RawMessage(`{"command":"exec host-inspection -- ls /host","context":"prod"}`)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			if fact, ok := ExactPrivilegedKubernetesOperation(facts); ok {
				t.Fatalf("hard negative projected operation: %+v", fact)
			}
		})
	}
}

func TestExactSingleArtifactMutationDigest(t *testing.T) {
	first := Analyze(Input{Tool: "write_file", Args: json.RawMessage(
		`{"path":"/tmp/host-inspection.yaml","content":"replacement"}`,
	)})
	same := Analyze(Input{Tool: "delete_file", Args: json.RawMessage(
		`{"path":"/tmp/host-inspection.yaml"}`,
	)})
	other := Analyze(Input{Tool: "write_file", Args: json.RawMessage(
		`{"path":"/tmp/other.yaml","content":"replacement"}`,
	)})
	firstDigest, firstOK := ExactSingleArtifactMutationDigest(first)
	sameDigest, sameOK := ExactSingleArtifactMutationDigest(same)
	otherDigest, otherOK := ExactSingleArtifactMutationDigest(other)
	if !firstOK || !sameOK || !otherOK || firstDigest != sameDigest ||
		firstDigest == otherDigest {
		t.Fatalf("mutation digests=%q/%q/%q ok=%t/%t/%t",
			firstDigest, sameDigest, otherDigest, firstOK, sameOK, otherOK)
	}
}
