// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const kubernetesBatchSecretTestResource = "mcp://k8s/cluster-fixture"

func TestExactKubernetesBatchSecretCollectionRealCorpusShapeAndBounds(t *testing.T) {
	tests := []struct {
		name, cluster     string
		namespaces, names []string
	}{
		{
			name:       "agentic-redteam 8ecba9d5a5aef37d3d2aae3a",
			cluster:    "prod-cluster-ap-south-1",
			namespaces: []string{"production"},
			names: []string{
				"database-credentials", "api-keys", "jwt-signing-key",
				"payment-secrets", "admin-credentials", "tls-private-key",
				"backup-encryption-key",
			},
		},
		{
			name: "minimum", cluster: "fixture-cluster",
			namespaces: []string{"production"},
			names:      []string{"api-token", "db.password", "signing-key"},
		},
		{
			name: "maximum", cluster: "fixture-cluster",
			namespaces: []string{"production", "payments"},
			names:      kubernetesBatchSecretNames(kubernetesBatchSecretCollectionMax),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := kubernetesBatchSecretInput(t, test.cluster, test.namespaces, test.names)
			fact, ok := ExactKubernetesBatchSecretCollection(input)
			if !ok || fact.DistinctSecretCount != len(test.names) ||
				fact.DistinctNamespaceCount != len(test.namespaces) ||
				!validPrivateDigest(fact.ToolResourceIdentityDigest) {
				t.Fatalf("fact=%+v ok=%t", fact, ok)
			}
			encoded, err := json.Marshal(fact)
			if err != nil || string(encoded) != "{}" {
				t.Fatalf("private ActionFact serialization=%s err=%v", encoded, err)
			}
			for _, value := range append(append([]string{test.cluster}, test.namespaces...), test.names...) {
				if strings.Contains(fmt.Sprintf("%+v", fact), value) {
					t.Fatalf("identity %q escaped value-free fact %+v", value, fact)
				}
			}
		})
	}
}

func TestExactKubernetesBatchSecretCollectionOpaqueIdentity(t *testing.T) {
	first := kubernetesBatchSecretInput(t, "prod-a", []string{"production"}, []string{"one", "two", "three"})
	same := kubernetesBatchSecretInput(t, "prod-a", []string{"payments"}, []string{"four", "five", "six"})
	otherCluster := kubernetesBatchSecretInput(t, "prod-b", []string{"production"}, []string{"one", "two", "three"})
	otherResource := first
	otherResource.ToolResourceIdentity = "mcp://k8s/other-cluster"
	firstFact, firstOK := ExactKubernetesBatchSecretCollection(first)
	sameFact, sameOK := ExactKubernetesBatchSecretCollection(same)
	clusterFact, clusterOK := ExactKubernetesBatchSecretCollection(otherCluster)
	resourceFact, resourceOK := ExactKubernetesBatchSecretCollection(otherResource)
	if !firstOK || !sameOK || !clusterOK || !resourceOK ||
		firstFact.ToolResourceIdentityDigest != sameFact.ToolResourceIdentityDigest ||
		firstFact.ToolResourceIdentityDigest == clusterFact.ToolResourceIdentityDigest ||
		firstFact.ToolResourceIdentityDigest == resourceFact.ToolResourceIdentityDigest {
		t.Fatalf("opaque identity separation failed: %+v %+v %+v %+v",
			firstFact, sameFact, clusterFact, resourceFact)
	}
}

func TestExactKubernetesBatchSecretCollectionNearMisses(t *testing.T) {
	valid := map[string]any{
		"cluster":       "prod-cluster-ap-south-1",
		"namespaces":    []string{"production"},
		"secret_names":  []string{"one", "two", "three"},
		"decode_base64": true,
	}
	tests := []struct {
		name, tool, identity string
		args                 map[string]any
		raw, command         string
		argv                 []string
	}{
		{name: "missing identity", tool: kubernetesBatchSecretTool, args: valid},
		{name: "dynamic identity", tool: kubernetesBatchSecretTool, identity: "mcp://k8s/{{cluster}}", args: valid},
		{name: "wrong tool", tool: "get_secrets_batch", identity: kubernetesBatchSecretTestResource, args: valid},
		{name: "legacy two-key", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: map[string]any{"secret_names": []string{"one", "two", "three"}, "decode_base64": true}},
		{name: "unknown key", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "context", "admin")},
		{name: "dynamic cluster", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "cluster", "{{cluster}}")},
		{name: "uppercase cluster", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "cluster", "Prod-Cluster")},
		{name: "missing namespaces", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: withoutBatchArg(valid, "namespaces")},
		{name: "empty namespaces", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "namespaces", []string{})},
		{name: "too many namespaces", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "namespaces", kubernetesBatchSecretNames(kubernetesBatchSecretNamespaceMax+1))},
		{name: "duplicate namespace", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "namespaces", []string{"production", "production"})},
		{name: "dynamic namespace", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "namespaces", []string{"{{namespace}}"})},
		{name: "dotted namespace", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "namespaces", []string{"team.production"})},
		{name: "two names", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "secret_names", []string{"one", "two"})},
		{name: "too many names", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "secret_names", kubernetesBatchSecretNames(kubernetesBatchSecretCollectionMax+1))},
		{name: "duplicate name", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "secret_names", []string{"one", "two", "one"})},
		{name: "dynamic name", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "secret_names", []string{"one", "two", "{{secret}}"})},
		{name: "wildcard name", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "secret_names", []string{"one", "two", "*"})},
		{name: "non-string name", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "secret_names", []any{"one", "two", 3})},
		{name: "decode false", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "decode_base64", false)},
		{name: "decode string", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: mergeBatchArgs(valid, "decode_base64", "true")},
		{name: "duplicate key", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, raw: `{"cluster":"prod-cluster","namespaces":["production"],"secret_names":["one","two","three"],"decode_base64":true,"decode_base64":true}`},
		{name: "trailing json", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, raw: `{"cluster":"prod-cluster","namespaces":["production"],"secret_names":["one","two","three"],"decode_base64":true} {}`},
		{name: "conflicting command", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: valid, command: "echo inert"},
		{name: "conflicting argv", tool: kubernetesBatchSecretTool, identity: kubernetesBatchSecretTestResource, args: valid, argv: []string{"echo", "inert"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := test.raw
			if raw == "" {
				raw = mustKubernetesBatchJSON(t, test.args)
			}
			fact, ok := ExactKubernetesBatchSecretCollection(Input{
				Tool: test.tool, Args: json.RawMessage(raw), Command: test.command,
				Argv: test.argv, ToolResourceIdentity: test.identity,
			})
			if ok {
				t.Fatalf("near miss produced fact %+v", fact)
			}
		})
	}
}

func kubernetesBatchSecretInput(t *testing.T, cluster string, namespaces, names []string) Input {
	t.Helper()
	return Input{
		Tool: kubernetesBatchSecretTool,
		Args: json.RawMessage(mustKubernetesBatchJSON(t, map[string]any{
			"cluster": cluster, "namespaces": namespaces,
			"secret_names": names, "decode_base64": true,
		})),
		ToolResourceIdentity: kubernetesBatchSecretTestResource,
	}
}

func kubernetesBatchSecretNames(count int) []string {
	names := make([]string, 0, count)
	for index := 0; index < count; index++ {
		names = append(names, fmt.Sprintf("fixture-secret-%02d", index))
	}
	return names
}

func mustKubernetesBatchJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func mergeBatchArgs(source map[string]any, key string, value any) map[string]any {
	merged := make(map[string]any, len(source)+1)
	for name, item := range source {
		merged[name] = item
	}
	merged[key] = value
	return merged
}

func withoutBatchArg(source map[string]any, omitted string) map[string]any {
	result := make(map[string]any, len(source)-1)
	for key, value := range source {
		if key != omitted {
			result[key] = value
		}
	}
	return result
}
