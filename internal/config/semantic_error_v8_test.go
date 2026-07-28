// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestObservabilityV8SemanticErrorPathTraversal(t *testing.T) {
	document, err := ParseV8YAML("semantic.yaml", []byte(`config_version: 8
data_dir: /tmp/defenseclaw
observability:
  buckets:
    model.io:
      redaction_profile: missing
  destinations:
    - name: archive
      kind: http_jsonl
      batch:
        max_queue_size: 10
        max_export_batch_size: 11
`))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		path  string
		kind  yaml.Kind
		value string
		line  int
	}{
		{name: "root", path: "$", kind: yaml.MappingNode, line: 1},
		{name: "dotted mapping key", path: "$.observability.buckets.model.io.redaction_profile", kind: yaml.ScalarNode, value: "missing", line: 6},
		{name: "quoted mapping key", path: `$.observability.buckets["model.io"].redaction_profile`, kind: yaml.ScalarNode, value: "missing", line: 6},
		{name: "mapping and sequence", path: "$.observability.destinations[0].batch.max_export_batch_size", kind: yaml.ScalarNode, value: "11", line: 12},
		{name: "missing mapping child returns nearest node", path: "$.observability.destinations[0].missing", kind: yaml.MappingNode, line: 8},
		{name: "out of range index returns sequence", path: "$.observability.destinations[4]", kind: yaml.SequenceNode, line: 8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := observabilityV8YAMLNodeAtPath(document, test.path)
			if node == nil || node.Kind != test.kind || node.Value != test.value || node.Line != test.line {
				t.Fatalf("node = %#v, want kind=%d value=%q line=%d", node, test.kind, test.value, test.line)
			}
		})
	}
}

func TestObservabilityV8SemanticErrorLocatesDottedMappingKey(t *testing.T) {
	_, err := ParseCompileObservabilityV8("semantic.yaml", []byte(`config_version: 8
data_dir: /tmp/defenseclaw
observability:
  buckets:
    model.io:
      redaction_profile: missing
`), ObservabilityV8CompileOptions{})
	var semanticError *V8SemanticError
	if !errors.As(err, &semanticError) {
		t.Fatalf("error = %T, want *V8SemanticError: %v", err, err)
	}
	if semanticError.Path != "$.observability.buckets.model.io.redaction_profile" ||
		semanticError.Line != 6 || semanticError.ReceivedClass != "string" {
		t.Fatalf("dotted-key semantic error = %#v", semanticError)
	}
}

func TestObservabilityV8SemanticErrorPathExtraction(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nested compiler path", err: errors.New("observability.destinations[12].batch.max_queue_size: invalid"), want: "$.observability.destinations[12].batch.max_queue_size"},
		{name: "data directory fallback", err: errors.New("DefaultDataDir is required"), want: "$.data_dir"},
		{name: "unknown fallback", err: errors.New("unclassified compiler failure"), want: "$"},
		{name: "secret reference", err: &V8SecretReferenceError{Path: "observability.destinations[0].token_env"}, want: "$.observability.destinations[0].token_env"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := observabilityV8SemanticErrorPath(test.err); got != test.want {
				t.Fatalf("path = %q, want %q", got, test.want)
			}
		})
	}
}
