// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func hx2CodexBash(t *testing.T, pack, command string) codexHookResponse {
	t.Helper()
	const connector = "codex"
	installToolCallCorpusProfileConnector(t, connector, pack)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
	return (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
		HookEventName: "PreToolUse", ToolName: "Bash", CWD: "/repo",
		ToolInput: map[string]interface{}{"command": command},
	})
}

func hx2RuleIDs(r codexHookResponse) []string {
	var ids []string
	for _, finding := range r.Findings {
		id, _, _ := strings.Cut(finding, ":")
		ids = append(ids, strings.TrimSpace(id))
	}
	return ids
}

var hx2Packs = []string{"default", "strict", "permissive"}

// rel-1-0-10:GAP-1925: a SQL client run in a container through kubectl, oc
// or k exec is read as the client call: the database rule the plain client
// call raises is raised, at the same action, in every pack. The pod exec
// keeps its own cells (lateral.workload_exec recorded in strict), and a
// command in the pod that is no SQL client raises nothing new.
func TestGAP1925PodExecSQLClientReadsAsTheClient(t *testing.T) {
	for _, row := range []struct{ wrapper, client, rule string }{
		{"kubectl exec db-0 --", `psql -d production -c "COPY t (c) TO PROGRAM 'id'"`, postgreSQLCopyProgramRuleID},
		{"kubectl exec -i -n prod db-0 -c db --", `psql -d production -c "COPY t (c) TO PROGRAM 'id'"`, postgreSQLCopyProgramRuleID},
		{"oc exec db-0 --", `psql -d production -c "COPY t (c) TO PROGRAM 'id'"`, postgreSQLCopyProgramRuleID},
		{"k exec db-0 --", `psql -d production -c "COPY t (c) TO PROGRAM 'id'"`, postgreSQLCopyProgramRuleID},
		{"kubectl exec db-0 -c db --", `mysql -h db -e "SELECT LOAD_FILE('/etc/shadow')"`, "secrets.sql_sensitive_server_file_read"},
		{"kubectl exec db-0 --", `psql -d production -c "DROP DATABASE production"`, "impact.sql_destructive_mutation"},
	} {
		for _, pack := range hx2Packs {
			plain := hx2CodexBash(t, pack, row.client)
			if !slices.Contains(hx2RuleIDs(plain), row.rule) {
				t.Fatalf("%s: plain %q gives %s %v; the premise is broken", pack, row.client, plain.Action, plain.Findings)
			}
			got := hx2CodexBash(t, pack, row.wrapper+" "+row.client)
			if got.Action != plain.Action || !slices.Contains(hx2RuleIDs(got), row.rule) {
				t.Errorf("%s: %q gives %s %v, want %s with %s as the plain client",
					pack, row.wrapper+" "+row.client, got.Action, got.Findings, plain.Action, row.rule)
			}
		}
	}
}

func TestGAP1925PodExecOtherCommandsRaiseNothingNew(t *testing.T) {
	for _, command := range []string{
		`kubectl exec db-0 -- psql -d production -c "SELECT 1"`,
		`kubectl exec web-0 -- cat /home/alice/.ssh/id_rsa`,
		`kubectl exec web-0 -- sh -c "rm -rf /tmp/cache"`,
		`kubectl exec web-0 -- ls /`,
	} {
		for _, pack := range hx2Packs {
			got := hx2CodexBash(t, pack, command)
			ids := slices.DeleteFunc(hx2RuleIDs(got), func(id string) bool { return id == "lateral.workload_exec" })
			if got.Action != "allow" || len(ids) != 0 {
				t.Errorf("%s: %q gives %s %v, want allow with at most the workload exec record", pack, command, got.Action, got.Findings)
			}
		}
	}
}

// rel-1-0-10:GAP-1860: a Kubernetes API path on a host not known as an
// apiserver (a bare IP:443) with a bearer token is a Kubernetes request: a
// Secret list over it takes the Secret read cells of the in-cluster form. The
// same path with no bearer token, and a bearer call to a path that is no
// Secret read, raise nothing.
func TestGAP1860BearerAPIPathIsKubernetesRequest(t *testing.T) {
	reference := `curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets`
	for _, command := range []string{
		`curl -k -H "Authorization: Bearer $TOKEN" https://10.0.0.1:443/api/v1/secrets`,
		`curl -k -H "authorization: bearer $TOKEN" https://10.0.0.1/api/v1/namespaces/prod/secrets/db`,
		`curl -sk --oauth2-bearer "$TOKEN" https://203.0.113.7/api/v1/secrets`,
		`wget --header="Authorization: Bearer $TOKEN" -qO- https://10.0.0.1:443/api/v1/secrets`,
	} {
		for _, pack := range hx2Packs {
			want := hx2CodexBash(t, pack, reference)
			got := hx2CodexBash(t, pack, command)
			if got.Action != want.Action || !slices.Contains(hx2RuleIDs(got), kubernetesNamedSecretReadRuleID) {
				t.Errorf("%s: %q gives %s %v, want %s with %s", pack, command, got.Action, got.Findings, want.Action, kubernetesNamedSecretReadRuleID)
			}
		}
	}
	for _, command := range []string{
		`curl -k https://10.0.0.1:443/api/v1/secrets`,
		`curl -k -H "Authorization: Bearer $TOKEN" https://api.example.com/api/v1/users`,
		`curl -k -H "Authorization: Bearer $TOKEN" https://10.0.0.1/apis/apps/v1/deployments`,
		`curl -k -H "X-Note: Authorization: Bearer" https://10.0.0.1/api/v1/secrets`,
	} {
		for _, pack := range hx2Packs {
			if got := hx2CodexBash(t, pack, command); got.Action != "allow" || len(got.Findings) != 0 {
				t.Errorf("%s: benign %q gives %s %v, want allow", pack, command, got.Action, got.Findings)
			}
		}
	}
}

// rel-1-0-10:GAP-1861: kubectl attach -i streams stdin into the container as
// exec -i does and takes the same cells (recorded in strict, inert in default
// and permissive); a shell kubectl get secrets -A lists names only and keeps
// its 1.0.10 cell, allow with no finding in every tier (1.0.10 decides that
// shape nowhere; only the structured kubectl tool alerts on it, as at
// 1.0.10); the Secret read rule title no longer says one named Secret.
func TestGAP1861AttachAndNamesOnlySecretList(t *testing.T) {
	for _, pair := range [][2]string{
		{"kubectl attach -i web-0", "kubectl exec -i web-0 -- sh"},
		{"kubectl attach -it web-0", "kubectl exec -it web-0 -- sh"},
		{"oc attach -i web-0 -c app", "oc exec -i web-0 -c app -- sh"},
	} {
		for _, pack := range hx2Packs {
			want := hx2CodexBash(t, pack, pair[1])
			got := hx2CodexBash(t, pack, pair[0])
			if got.Action != want.Action || !slices.Equal(hx2RuleIDs(got), hx2RuleIDs(want)) {
				t.Errorf("%s: %q gives %s %v, want %s %v as %q", pack, pair[0], got.Action, got.Findings, want.Action, want.Findings, pair[1])
			}
		}
	}
	for _, pack := range hx2Packs {
		if got := hx2CodexBash(t, pack, "kubectl attach web-0"); len(got.Findings) != 0 {
			t.Errorf("%s: kubectl attach without stdin gives %v, want no finding", pack, got.Findings)
		}
	}
	for _, command := range []string{"kubectl get secrets -A", "kubectl get secrets --all-namespaces", "kubectl get secret -A -o name"} {
		for _, pack := range hx2Packs {
			if got := hx2CodexBash(t, pack, command); got.Action != "allow" || len(got.Findings) != 0 {
				t.Errorf("%s: %q gives %s %v, want allow with no finding (the 1.0.10 cell)", pack, command, got.Action, got.Findings)
			}
		}
	}
	for _, pack := range hx2Packs {
		if got := hx2CodexBash(t, pack, "kubectl get secrets -n prod"); len(got.Findings) != 0 {
			t.Errorf("%s: a namespaced Secret name list gives %v, want no finding", pack, got.Findings)
		}
		got := hx2CodexBash(t, pack, "kubectl get secrets -A -o yaml")
		for _, finding := range got.Findings {
			if strings.Contains(finding, "one named") {
				t.Errorf("%s: finding title still says one named Secret: %q", pack, finding)
			}
		}
	}
}
