// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStructuredLiteralPersistenceMCPHuntShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input Input
		class StructuredLiteralPersistenceSink
		count int
	}{
		{
			name: "write file",
			input: Input{
				Tool:                 "write_file",
				Args:                 json.RawMessage(`{"path":"/synthetic/report.txt","content":"synthetic row value for lineage test"}`),
				ToolResourceIdentity: "mcp://filesystem/synthetic-workspace",
			},
			class: StructuredLiteralPersistenceFile, count: 1,
		},
		{
			name: "create entities",
			input: Input{
				Tool:                 "create_entities",
				Args:                 json.RawMessage(`{"entities":[{"entityType":"SyntheticReport","name":"synthetic report one","observations":["synthetic row value for lineage test"]},{"entityType":"SyntheticReport","name":"synthetic report two","observations":["another synthetic observation"]}]}`),
				ToolResourceIdentity: "mcp://memory/synthetic-graph",
			},
			class: StructuredLiteralPersistenceEntity, count: 2,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(test.input)
			persistences := ExactStructuredLiteralPersistences(facts)
			if len(persistences) != test.count {
				t.Fatalf("persistences = %#v, parse = %#v", persistences, facts.Parse)
			}
			for _, persistence := range persistences {
				if persistence.SinkClass != test.class || !persistence.Exact ||
					!validPrivateDigest(persistence.TargetIdentityDigest) {
					t.Fatalf("persistence = %#v", persistence)
				}
			}
		})
	}
}

func TestStructuredLiteralPersistenceRejectsAmbiguousSchemas(t *testing.T) {
	t.Parallel()
	tests := []Input{
		{Tool: "write_file", Args: json.RawMessage(`{"path":"/synthetic/out","content":"literal"}`)},
		{Tool: "write_file", Args: json.RawMessage(`{"path":"${OUTPUT}","content":"literal"}`), ToolResourceIdentity: "mcp://filesystem/synthetic"},
		{Tool: "write_file", Args: json.RawMessage(`{"path":"/synthetic/out","content":"${UNRESOLVED}"}`), ToolResourceIdentity: "mcp://filesystem/synthetic"},
		{Tool: "write_file", Args: json.RawMessage(`{"path":"/synthetic/out","content":"literal","mode":"append"}`), ToolResourceIdentity: "mcp://filesystem/synthetic"},
		{Tool: "write_file", Args: json.RawMessage(`{"path":"/synthetic/out","content":"literal","tool_resource_identity":"mcp://filesystem/attacker-chosen"}`)},
		{Tool: "write_file", Args: json.RawMessage(`{"path":"/synthetic/out","path":"/synthetic/other","content":"literal"}`), ToolResourceIdentity: "mcp://filesystem/synthetic"},
		{Tool: "write_file", Args: json.RawMessage(`{"path":{"value":"/synthetic/out"},"content":"literal"}`), ToolResourceIdentity: "mcp://filesystem/synthetic"},
		{Tool: "create_entities", Args: json.RawMessage(`{"entities":[]}`), ToolResourceIdentity: "mcp://memory/synthetic"},
		{Tool: "create_entities", Args: json.RawMessage(`{"entities":[{"entityType":"Report","name":"${ENTITY}","observations":["literal"]}]}`), ToolResourceIdentity: "mcp://memory/synthetic"},
		{Tool: "create_entities", Args: json.RawMessage(`{"entities":[{"entityType":"Report","name":"one","observations":[{"text":"nested"}]}]}`), ToolResourceIdentity: "mcp://memory/synthetic"},
		{Tool: "create_entities", Args: json.RawMessage(`{"entities":[{"entityType":"Report","name":"one","observations":["{{ unresolved }}"]}]}`), ToolResourceIdentity: "mcp://memory/synthetic"},
		{Tool: "create_entities", Args: json.RawMessage(`{"entities":[{"entityType":"Report","name":"one","observations":["literal"],"metadata":{}}]}`), ToolResourceIdentity: "mcp://memory/synthetic"},
		{Tool: "create_entities", Args: json.RawMessage(`{"entities":[{"entityType":"Report","name":"one","observations":["literal"]},{"entityType":"Report","name":"one","observations":["other"]}]}`), ToolResourceIdentity: "mcp://memory/synthetic"},
		{Tool: "create_entities", Args: json.RawMessage(`{"entities":[{"entityType":"Report","entityType":"Other","name":"one","observations":["literal"]}]}`), ToolResourceIdentity: "mcp://memory/synthetic"},
		{Tool: "create_entities", Args: json.RawMessage(`{"entities":[{"entityType":"Report","name":"one","observations":["literal"]}],"path":"/synthetic/out"}`), ToolResourceIdentity: "mcp://memory/synthetic"},
	}
	for index, input := range tests {
		facts := Analyze(input)
		if persistences := ExactStructuredLiteralPersistences(facts); len(persistences) != 0 {
			t.Fatalf("case %d unexpected persistences: %#v", index, persistences)
		}
	}
}

func TestStructuredLiteralPersistenceRejectsOversizedValues(t *testing.T) {
	t.Parallel()
	oversizedContent, err := json.Marshal(map[string]string{
		"path":    "/synthetic/out",
		"content": strings.Repeat("x", maxCommandBytes+1),
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := Analyze(Input{
		Tool: "write_file", Args: oversizedContent,
		ToolResourceIdentity: "mcp://filesystem/synthetic",
	})
	if persistences := ExactStructuredLiteralPersistences(facts); len(persistences) != 0 {
		t.Fatalf("oversized content projected: %#v", persistences)
	}
}

func TestStructuredLiteralPersistenceIsDigestOnlyAndPrivate(t *testing.T) {
	t.Parallel()
	const (
		resource = "mcp://memory/synthetic-graph"
		name     = "synthetic private target"
		content  = "synthetic private row value for lineage test"
	)
	input := Input{
		Tool:                 "create_entities",
		Args:                 json.RawMessage(`{"entities":[{"entityType":"SyntheticReport","name":"` + name + `","observations":["` + content + `"]}]}`),
		ToolResourceIdentity: resource,
	}
	facts := Analyze(input)
	persistences := ExactStructuredLiteralPersistences(facts)
	if len(persistences) != 1 {
		t.Fatalf("persistences = %#v", persistences)
	}
	encodedInput, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedInput), resource) {
		t.Fatalf("trusted identity serialized in input: %s", encodedInput)
	}
	encodedFacts, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		resource, name, content, persistences[0].TargetIdentityDigest,
		"StructuredLiteralPersistences",
	} {
		if strings.Contains(string(encodedFacts), forbidden) {
			t.Fatalf("private persistence material %q serialized: %s", forbidden, encodedFacts)
		}
	}

	encodedFact, err := json.Marshal(persistences[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedFact), resource) ||
		strings.Contains(string(encodedFact), name) ||
		strings.Contains(string(encodedFact), content) {
		t.Fatalf("raw material present in persistence fact: %s", encodedFact)
	}
}
