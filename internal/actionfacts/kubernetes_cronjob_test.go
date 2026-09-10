// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestKubernetesCronJobActualHFShapesAndOpaqueJoin(t *testing.T) {
	tests := []struct {
		name     string
		patch    string
		create   string
		hostRoot bool
	}{
		{
			name:   "json privileged",
			patch:  `{"command":"patch cronjob daily-backup --type='json' -p='[{\"op\":\"add\",\"path\":\"/spec/jobTemplate/spec/template/spec/containers/0/securityContext\",\"value\":{\"privileged\":true}}]'","namespace":"production"}`,
			create: `{"command":"create job --from=cronjob/daily-backup test-escape","namespace":"production"}`,
		},
		{
			name:     "json host root redundant namespace",
			patch:    `{"command":"patch cronjob data-processor -n staging --type=json -p='[{\"op\":\"replace\",\"path\":\"/spec/jobTemplate/spec/template/spec/containers/0/securityContext\",\"value\":{\"privileged\":true}},{\"op\":\"add\",\"path\":\"/spec/jobTemplate/spec/template/spec/containers/0/volumeMounts\",\"value\":[{\"name\":\"host-root\",\"mountPath\":\"/host\"}]},{\"op\":\"add\",\"path\":\"/spec/jobTemplate/spec/template/spec/volumes\",\"value\":[{\"name\":\"host-root\",\"hostPath\":{\"path\":\"/\"}}]}]'","namespace":"staging"}`,
			create:   `{"command":"create job data-processor-now --from=cronjob/data-processor","namespace":"staging"}`,
			hostRoot: true,
		},
		{
			name:     "json host root command namespace",
			patch:    `{"command":"patch cronjob backup -n default --type json -p '[{\"op\": \"add\", \"path\": \"/spec/jobTemplate/spec/template/spec/containers/0/securityContext\", \"value\": {\"privileged\": true}}, {\"op\": \"add\", \"path\": \"/spec/jobTemplate/spec/template/spec/volumes\", \"value\": [{\"name\": \"host-root\", \"hostPath\": {\"path\": \"/\"}}]}, {\"op\": \"add\", \"path\": \"/spec/jobTemplate/spec/template/spec/containers/0/volumeMounts\", \"value\": [{\"name\": \"host-root\", \"mountPath\": \"/host\"}]}]'"}`,
			create:   `{"command":"create job --from=cronjob/backup backup-exploit -n default"}`,
			hostRoot: true,
		},
		{
			name:   "merge privileged command namespace",
			patch:  `{"command":"patch cronjob cleanup-job -n kube-system --patch '{\"spec\":{\"jobTemplate\":{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"main\",\"securityContext\":{\"privileged\":true}}]}}}}}}'"}`,
			create: `{"command":"create job manual-trigger --from=cronjob/cleanup-job -n kube-system"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			patch := Analyze(Input{Tool: "kubectl", Args: json.RawMessage(test.patch)})
			create := Analyze(Input{Tool: "kubectl", Args: json.RawMessage(test.create)})
			patchFact, patchOK := ExactKubernetesCronJobOperation(patch)
			createFact, createOK := ExactKubernetesCronJobOperation(create)
			if !patchOK || !createOK ||
				patchFact.Operation != KubernetesCronJobPrivilegedPatch ||
				createFact.Operation != KubernetesCronJobCreateFrom ||
				patchFact.CronJobIdentityDigest != createFact.CronJobIdentityDigest ||
				patchFact.HostRoot != test.hostRoot || createFact.HostRoot {
				t.Fatalf("patch/create=%+v/%+v facts=%+v/%+v", patch, create, patchFact, createFact)
			}
			if patchFact.CronJobIdentityDigest == "" ||
				patchFact.CronJobIdentityDigest == "data-cronjob" ||
				patchFact.CronJobIdentityDigest == "production" {
				t.Fatalf("raw identity escaped projection: %+v", patchFact)
			}
		})
	}
}

func TestKubernetesCronJobHardNegatives(t *testing.T) {
	privileged := `[{"op":"add","path":"/spec/jobTemplate/spec/template/spec/containers/0/securityContext","value":{"privileged":true}}]`
	hostRootWithoutMount := `[{"op":"add","path":"/spec/jobTemplate/spec/template/spec/containers/0/securityContext","value":{"privileged":true}},{"op":"add","path":"/spec/jobTemplate/spec/template/spec/volumes","value":[{"name":"host-root","hostPath":{"path":"/"}}]}]`
	tests := []struct {
		name string
		raw  string
	}{
		{name: "dynamic patch name", raw: kubectlCronJobArgs(t, `patch cronjob "$TARGET" --type=json -p='`+privileged+`'`, "production")},
		{name: "unknown structured field", raw: `{"command":"patch cronjob backup --type=json -p='[]'","namespace":"default","context":"prod"}`},
		{name: "generic privileged text", raw: `{"command":"get cronjob backup -o jsonpath='{.spec.jobTemplate.spec.template.spec.containers[0].securityContext.privileged}'","namespace":"default"}`},
		{name: "partial host root", raw: kubectlCronJobArgs(t, `patch cronjob backup --type=json -p='`+hostRootWithoutMount+`'`, "default")},
		{name: "privileged false", raw: kubectlCronJobArgs(t, `patch cronjob backup --type=json -p='[{"op":"replace","path":"/spec/jobTemplate/spec/template/spec/containers/0/securityContext","value":{"privileged":false}}]'`, "default")},
		{name: "unknown patch flag", raw: kubectlCronJobArgs(t, `patch cronjob backup --dry-run=server --type=json -p='`+privileged+`'`, "default")},
		{name: "namespace mismatch", raw: kubectlCronJobArgs(t, `patch cronjob backup -n staging --type=json -p='`+privileged+`'`, "production")},
		{name: "invalid dotted namespace", raw: kubectlCronJobArgs(t, `patch cronjob backup --type=json -p='`+privileged+`'`, "prod.cluster")},
		{name: "noncanonical container index", raw: kubectlCronJobArgs(t, `patch cronjob backup --type=json -p='[{"op":"add","path":"/spec/jobTemplate/spec/template/spec/containers/00/securityContext","value":{"privileged":true}}]'`, "default")},
		{name: "dynamic source", raw: kubectlCronJobArgs(t, `create job exploit --from=cronjob/$SOURCE`, "default")},
		{name: "missing job name", raw: kubectlCronJobArgs(t, `create job --from=cronjob/backup`, "default")},
		{name: "unrelated create", raw: kubectlCronJobArgs(t, `create job exploit --image=busybox`, "default")},
		{name: "extra create flag", raw: kubectlCronJobArgs(t, `create job exploit --from=cronjob/backup --dry-run=server`, "default")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "kubectl", Args: json.RawMessage(test.raw)})
			if fact, ok := ExactKubernetesCronJobOperation(facts); ok &&
				fact.Operation == KubernetesCronJobPrivilegedPatch {
				t.Fatalf("hard negative projected operation: %+v facts=%+v", fact, facts)
			}
		})
	}

	for _, input := range []Input{
		{Tool: "execute_command", Command: `kubectl patch cronjob backup --type=json -p='` + privileged + `'`},
		{Tool: "shell", Command: `echo "kubectl patch cronjob backup privileged true"`},
	} {
		if fact, ok := ExactKubernetesCronJobOperation(Analyze(input)); ok {
			t.Fatalf("inert/non-structured input projected operation: %+v", fact)
		}
	}
}

func TestKubernetesCronJobNonPrivilegedPatchIsIdentityBoundBarrier(t *testing.T) {
	input := Input{Tool: "kubectl", Args: json.RawMessage(kubectlCronJobArgs(
		t,
		`patch cronjob backup --type=json -p='[{"op":"replace","path":"/spec/jobTemplate/spec/template/spec/containers/0/securityContext","value":{"privileged":false}}]'`,
		"production",
	))}
	fact, ok := ExactKubernetesCronJobOperation(Analyze(input))
	if !ok || fact.Operation != KubernetesCronJobPatchBarrier ||
		fact.CronJobIdentityDigest == "" || fact.HostRoot {
		t.Fatalf("barrier=%+v ok=%t", fact, ok)
	}
}

func TestKubernetesCronJobIdentityRequiresNamespaceAndNameMatch(t *testing.T) {
	patch := Analyze(Input{Tool: "kubectl", Args: json.RawMessage(kubectlCronJobArgs(
		t,
		`patch cronjob backup --type=json -p='[{"op":"add","path":"/spec/jobTemplate/spec/template/spec/containers/0/securityContext","value":{"privileged":true}}]'`,
		"default",
	))})
	for _, createArgs := range []string{
		kubectlCronJobArgs(t, `create job exploit --from=cronjob/other`, "default"),
		kubectlCronJobArgs(t, `create job exploit --from=cronjob/backup`, "staging"),
	} {
		patchFact, patchOK := ExactKubernetesCronJobOperation(patch)
		createFact, createOK := ExactKubernetesCronJobOperation(Analyze(Input{
			Tool: "kubectl", Args: json.RawMessage(createArgs),
		}))
		if !patchOK || !createOK || patchFact.CronJobIdentityDigest == createFact.CronJobIdentityDigest {
			t.Fatalf("identity mismatch was not preserved: %+v/%+v", patchFact, createFact)
		}
	}
}

func kubectlCronJobArgs(t *testing.T, command, namespace string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"command": command, "namespace": namespace})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
