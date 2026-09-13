// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestKubernetesPrivilegedPodRunExact(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		namespace   string
		hostPID     bool
		hostNetwork bool
	}{
		{name: "flag", command: "run inspector --image=busybox --privileged --restart=Never", namespace: "prod"},
		{name: "flag true", command: "run inspector --image busybox --privileged=true"},
		{name: "override", command: `run inspector --image=busybox --overrides='{"apiVersion":"v1","spec":{"containers":[{"securityContext":{"privileged":true}}],"hostPID":true,"hostNetwork":true}}'`, hostPID: true, hostNetwork: true},
		{name: "realistic override", command: `run inspector --image=alpine --restart=Never --overrides='{"spec":{"containers":[{"name":"inspector","image":"alpine","securityContext":{"privileged":true},"command":["sleep","3600"]}]}}'`},
		{name: "linked host root override", command: `run inspector --image=alpine --restart=Never --overrides='{"spec":{"containers":[{"name":"inspector","image":"alpine","command":["sleep","3600"],"securityContext":{"privileged":true},"volumeMounts":[{"name":"host-root","mountPath":"/host"}]}],"volumes":[{"name":"host-root","hostPath":{"path":"/","type":"Directory"}}]}}'`},
		{name: "flag with linked host root override", command: `run inspector --image=alpine --privileged --overrides='{"spec":{"containers":[{"name":"inspector","image":"alpine","command":["sleep","3600"],"volumeMounts":[{"name":"host","mountPath":"/host-root"}]}],"volumes":[{"name":"host","hostPath":{"path":"/"}}]}}'`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"command": test.command, "namespace": test.namespace})
			if err != nil {
				t.Fatal(err)
			}
			if test.namespace == "" {
				raw, err = json.Marshal(map[string]string{"command": test.command})
				if err != nil {
					t.Fatal(err)
				}
			}
			fact, ok := ExactKubernetesPodRun(Analyze(Input{Tool: "kubectl", Args: raw}))
			if !ok || !fact.Privileged || fact.HostPID != test.hostPID ||
				fact.HostNetwork != test.hostNetwork || !validPrivateDigest(fact.PodIdentityDigest) {
				t.Fatalf("fact=%+v ok=%t", fact, ok)
			}
		})
	}
}

func TestKubernetesPrivilegedPodRunHardNegatives(t *testing.T) {
	commands := []string{
		"run inspector --image=busybox",
		"run inspector --image=busybox --privileged=false",
		"run inspector --image=busybox --privileged --dry-run=client",
		"run inspector --image=busybox -- --privileged",
		"run inspector --image=busybox --command -- sleep infinity --privileged",
		`run inspector --image=busybox --overrides='{"spec":{"containers":[{"securityContext":{"privileged":false}}]}}'`,
		`run inspector --image=busybox --overrides='{"spec":{"containers":[{"securityContext":{"privileged":true,"runAsUser":0}}]}}'`,
		`run inspector --image=busybox --overrides='{"spec":{"containers":[{"securityContext":{"privileged":true}}],"unknown":true}}'`,
		`run inspector --image=busybox --overrides='{"spec":{"containers":[{"name":"inspector","image":"busybox","securityContext":{"privileged":true},"unknown":true}]}}'`,
		`run inspector --image=busybox --overrides='{"spec":{"containers":[{"name":"inspector","image":"busybox","securityContext":{"privileged":true},"volumeMounts":[{"name":"host-a","mountPath":"/host"}]}],"volumes":[{"name":"host-b","hostPath":{"path":"/"}}]}}'`,
		`run inspector --image=busybox --overrides='{"spec":{"containers":[{"name":"inspector","image":"busybox","securityContext":{"privileged":true},"volumeMounts":[{"name":"host","mountPath":"/data"}]}],"volumes":[{"name":"host","hostPath":{"path":"/"}}]}}'`,
		`run inspector --image=busybox --overrides='{"spec":{"containers":[{"name":"inspector","image":"busybox","securityContext":{"privileged":true},"volumeMounts":[{"name":"host","mountPath":"/host"}]}],"volumes":[{"name":"host","hostPath":{"path":"/var"}}]}}'`,
		`run inspector --image=busybox --overrides='{"spec":{"containers":[{"name":"inspector","image":"$IMAGE","securityContext":{"privileged":true}}]}}'`,
		`run inspector --image=busybox --overrides='{"spec":{"containers":[{"name":"inspector","image":"busybox","command":["$COMMAND"],"securityContext":{"privileged":true}}]}}'`,
		`run inspector --image=busybox --overrides='{"spec":{"containers":[{"securityContext":{"privileged":true}}]}} trailing'`,
		"run $POD --image=busybox --privileged",
		"run inspector --image=$IMAGE --privileged",
		"run inspector --image=busybox --privileged --context=prod",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"command": command})
			if err != nil {
				t.Fatal(err)
			}
			if fact, ok := ExactKubernetesPodRun(Analyze(Input{Tool: "kubectl", Args: raw})); ok {
				t.Fatalf("hard negative projected: %+v", fact)
			}
		})
	}
}

func TestKubernetesPrivilegedPodRunRejectsSchemaAmbiguity(t *testing.T) {
	inputs := []json.RawMessage{
		json.RawMessage(`{"command":"run inspector --image=busybox --privileged","namespace":"prod","context":"other"}`),
		json.RawMessage(`{"command":"run inspector -n other --image=busybox --privileged","namespace":"prod"}`),
	}
	for _, raw := range inputs {
		if fact, ok := ExactKubernetesPodRun(Analyze(Input{Tool: "kubectl", Args: raw})); ok {
			t.Fatalf("ambiguous input projected: %+v", fact)
		}
	}
}
