// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseV8YAMLValidDocumentAndPlainProjection(t *testing.T) {
	document, err := ParseV8YAML("config.yaml", []byte(`config_version: 8
enabled: false
count: 7
ratio: 0.25
empty: null
timestamp: 2026-07-02
observability:
  resource:
    attributes:
      service.name: defenseclaw-gateway
  destinations:
    - name: collector
      enabled: true
      signals: [logs, traces, metrics]
`))
	if err != nil {
		t.Fatalf("ParseV8YAML: %v", err)
	}
	if document.Source != "config.yaml" || document.Document == nil || document.Document.Kind != yaml.DocumentNode {
		t.Fatalf("unexpected source/document: %q %#v", document.Source, document.Document)
	}
	if got := document.Plain["config_version"]; got != 8 {
		t.Fatalf("config_version = %#v, want int(8)", got)
	}
	if got := document.Plain["enabled"]; got != false {
		t.Fatalf("enabled = %#v, want false", got)
	}
	if got := document.Plain["empty"]; got != nil {
		t.Fatalf("empty = %#v, want nil", got)
	}
	if got := document.Plain["timestamp"]; got != "2026-07-02" {
		t.Fatalf("timestamp = %#v, want source string", got)
	}
	observability, ok := document.Plain["observability"].(map[string]any)
	if !ok {
		t.Fatalf("observability = %T, want map", document.Plain["observability"])
	}
	if destinations, ok := observability["destinations"].([]any); !ok || len(destinations) != 1 {
		t.Fatalf("destinations = %#v, want one-item slice", observability["destinations"])
	}
}

func TestParseV8YAMLVersionContract(t *testing.T) {
	for _, test := range []struct {
		name, source string
		code         V8YAMLErrorCode
	}{
		{"missing", "observability: {}\n", V8YAMLErrorVersionRequired},
		{"zero", "config_version: 0\n", V8YAMLErrorVersionUpgrade},
		{"past", "config_version: 7\n", V8YAMLErrorVersionUpgrade},
		{"future", "config_version: 9\n", V8YAMLErrorVersionUnsupported},
		{"negative", "config_version: -1\n", V8YAMLErrorVersionInvalid},
		{"quoted", "config_version: '8'\n", V8YAMLErrorVersionInvalid},
		{"float", "config_version: 8.0\n", V8YAMLErrorVersionInvalid},
		{"boolean", "config_version: true\n", V8YAMLErrorVersionInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := requireV8YAMLError(t, []byte(test.source), test.code)
			if err.Path != "$.config_version" || err.Action == "" {
				t.Fatalf("version error lacks path/action: %#v", err)
			}
		})
	}
}

func TestParseV8YAMLInvalidUTF8AndByteLimit(t *testing.T) {
	invalid := append([]byte("config_version: 8\nvalue: "), 0xff)
	requireV8YAMLError(t, invalid, V8YAMLErrorInvalidUTF8)

	prefix := []byte("config_version: 8\n#")
	atLimit := append(prefix, repeatedByte('x', V8YAMLMaxSourceBytes-len(prefix))...)
	if _, err := ParseV8YAML("config.yaml", atLimit); err != nil {
		t.Fatalf("source at byte limit rejected: %v", err)
	}
	requireV8YAMLError(t, append(atLimit, '\n'), V8YAMLErrorSourceTooLarge)
}

func TestParseV8YAMLDocumentAndRootShape(t *testing.T) {
	for _, test := range []struct {
		name, source string
		code         V8YAMLErrorCode
	}{
		{"empty", "", V8YAMLErrorRootMappingRequired},
		{"comments", "# comment\n", V8YAMLErrorRootMappingRequired},
		{"sequence", "- config_version\n- 8\n", V8YAMLErrorRootMappingRequired},
		{"scalar", "8\n", V8YAMLErrorRootMappingRequired},
		{"multiple", "config_version: 8\n---\nconfig_version: 8\n", V8YAMLErrorMultipleDocuments},
		{"empty second document", "config_version: 8\n---\n", V8YAMLErrorMultipleDocuments},
		{"malformed", "config_version: 8\nsecret: [do-not-echo\n", V8YAMLErrorSyntax},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := requireV8YAMLError(t, []byte(test.source), test.code)
			if strings.Contains(err.Error(), "do-not-echo") {
				t.Fatalf("syntax error leaked scalar: %s", err)
			}
		})
	}
}

func TestParseV8YAMLDuplicateKeysAtEveryLevel(t *testing.T) {
	for _, test := range []struct {
		name, source, path  string
		line, column        int
		firstLine, firstCol int
	}{
		{"root", "config_version: 8\nconfig_version: 8\n", "$.config_version", 2, 1, 1, 1},
		{"nested", "config_version: 8\nobservability:\n  defaults: {}\n  defaults: {}\n", "$.observability.defaults", 4, 3, 3, 3},
		{"sequence map", "config_version: 8\nitems:\n  - name: first\n    name: second\n", "$.items[0].name", 4, 5, 3, 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := requireV8YAMLError(t, []byte(test.source), V8YAMLErrorDuplicateKey)
			if err.Path != test.path || err.Line != test.line || err.Column != test.column {
				t.Fatalf("got %s %d:%d, want %s %d:%d", err.Path, err.Line, err.Column, test.path, test.line, test.column)
			}
			first := fmt.Sprintf("line %d, column %d", test.firstLine, test.firstCol)
			if !strings.Contains(err.Summary, first) {
				t.Fatalf("Summary = %q, want %q", err.Summary, first)
			}
		})
	}
}

func TestParseV8YAMLAliasMergeAndCustomTagRejection(t *testing.T) {
	requireV8YAMLError(t, []byte(`config_version: 8
template: &template {enabled: true}
copy: *template
`), V8YAMLErrorAliasForbidden)
	merge := requireV8YAMLError(t, []byte(`config_version: 8
template: &template {enabled: true}
merged:
  <<: *template
`), V8YAMLErrorMergeKeyForbidden)
	if merge.Line != 4 || merge.Column != 3 {
		t.Fatalf("merge location = %d:%d, want 4:3", merge.Line, merge.Column)
	}
	requireV8YAMLError(t, []byte("config_version: 8\nmerged:\n  <<: {enabled: true}\n"), V8YAMLErrorMergeKeyForbidden)

	for _, source := range []string{
		"config_version: 8\nvalue: !secret do-not-echo\n",
		"config_version: 8\nvalue: !custom {enabled: true}\n",
		"config_version: 8\n!custom key: value\n",
	} {
		err := requireV8YAMLError(t, []byte(source), V8YAMLErrorCustomTagForbidden)
		if strings.Contains(err.Error(), "do-not-echo") || strings.Contains(err.Error(), "!secret") {
			t.Fatalf("custom-tag error leaked tag/value: %s", err)
		}
	}
}

func TestParseV8YAMLNonStringMappingKey(t *testing.T) {
	err := requireV8YAMLError(t, []byte("config_version: 8\n1: value\n"), V8YAMLErrorMappingKeyInvalid)
	if err.Line != 2 || err.Column != 1 {
		t.Fatalf("location = %d:%d, want 2:1", err.Line, err.Column)
	}
}

func TestParseV8YAMLMappingEntryLimit(t *testing.T) {
	var allowed strings.Builder
	allowed.WriteString("config_version: 8\n")
	for index := 0; index < V8YAMLMaxMappingEntries-1; index++ {
		fmt.Fprintf(&allowed, "key_%04d: true\n", index)
	}
	if _, err := ParseV8YAML("config.yaml", []byte(allowed.String())); err != nil {
		t.Fatalf("mapping at entry limit rejected: %v", err)
	}
	requireV8YAMLError(t, []byte(allowed.String()+"one_more: true\n"), V8YAMLErrorMappingEntriesLimit)

	var nested strings.Builder
	nested.WriteString("config_version: 8\nnested:\n")
	for index := 0; index <= V8YAMLMaxMappingEntries; index++ {
		fmt.Fprintf(&nested, "  key_%04d: true\n", index)
	}
	err := requireV8YAMLError(t, []byte(nested.String()), V8YAMLErrorMappingEntriesLimit)
	if err.Path != "$.nested" {
		t.Fatalf("nested mapping limit Path = %q, want $.nested", err.Path)
	}
}

func TestParseV8YAMLDepthLimitRootIsOne(t *testing.T) {
	if _, err := ParseV8YAML("config.yaml", []byte(nestedV8YAML(V8YAMLMaxDepth-1))); err != nil {
		t.Fatalf("depth at limit rejected: %v", err)
	}
	requireV8YAMLError(t, []byte(nestedV8YAML(V8YAMLMaxDepth)), V8YAMLErrorDepthLimit)
	sequence := "config_version: 8\nnested: " + strings.Repeat("[", V8YAMLMaxDepth) +
		"true" + strings.Repeat("]", V8YAMLMaxDepth) + "\n"
	requireV8YAMLError(t, []byte(sequence), V8YAMLErrorDepthLimit)
}

func TestParseV8YAMLNodeLimitCountsKeysAndScalars(t *testing.T) {
	// root mapping, two keys, config version scalar, and sequence = five.
	allowedItems := V8YAMLMaxNodes - 5
	if _, err := ParseV8YAML("config.yaml", []byte(sequenceV8YAML(allowedItems))); err != nil {
		t.Fatalf("node count at limit rejected: %v", err)
	}
	requireV8YAMLError(t, []byte(sequenceV8YAML(allowedItems+1)), V8YAMLErrorNodeLimit)
}

func TestParseV8YAMLTargetedLegacyDiagnostics(t *testing.T) {
	for _, test := range []struct {
		name, body, path, target string
	}{
		{"otel", "otel: {}\n", "$.otel", "observability"},
		{"audit sinks", "audit_sinks: []\n", "$.audit_sinks", "observability.destinations"},
		{"audit db", "audit_db: /tmp/audit.db\n", "$.audit_db", "observability.local.path"},
		{"judge db", "judge_bodies_db: /tmp/judge.db\n", "$.judge_bodies_db", "observability.local.judge_bodies_path"},
		{"privacy", "privacy:\n  disable_redaction: false\n", "$.privacy.disable_redaction", "bucket policies"},
		{"discovery", "ai_discovery:\n  emit_otel: false\n", "$.ai_discovery.emit_otel", "ai.discovery"},
		{"splunk", "splunk: {}\n", "$.splunk", "splunk_hec"},
		{"connector sinks", "observability:\n  connectors:\n    codex:\n      audit_sinks: []\n", "$.observability.connectors.codex.audit_sinks", "connector selectors"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := requireV8YAMLError(t, []byte("config_version: 8\n"+test.body), V8YAMLErrorLegacyKeyForbidden)
			if err.Path != test.path {
				t.Fatalf("Path = %q, want %q", err.Path, test.path)
			}
			if !strings.Contains(err.Action, "defenseclaw upgrade") || !strings.Contains(err.Action, test.target) {
				t.Fatalf("Action = %q, want upgrade guidance with %q", err.Action, test.target)
			}
		})
	}
}

func TestParseV8YAMLConnectorWebhooksRemainsAllowed(t *testing.T) {
	_, err := ParseV8YAML("config.yaml", []byte(`config_version: 8
observability:
  connectors:
    codex:
      webhooks: []
`))
	if err != nil {
		t.Fatalf("webhooks compatibility child rejected: %v", err)
	}
}

func TestParseV8YAMLErrorsAreDeterministicAndSecretSafe(t *testing.T) {
	source := []byte("config_version: 8\nheaders:\n  Authorization: first-secret\n  Authorization: second-secret\n")
	first := requireV8YAMLError(t, source, V8YAMLErrorDuplicateKey).Error()
	second := requireV8YAMLError(t, source, V8YAMLErrorDuplicateKey).Error()
	if first != second {
		t.Fatalf("errors differ:\n%s\n%s", first, second)
	}
	for _, secret := range []string{"first-secret", "second-secret"} {
		if strings.Contains(first, secret) {
			t.Fatalf("error leaked %q: %s", secret, first)
		}
	}
	if !strings.Contains(first, "config.yaml:4:3") || !strings.Contains(first, string(V8YAMLErrorDuplicateKey)) {
		t.Fatalf("error lacks stable location/code: %s", first)
	}
}

func TestParseV8YAMLNonFiniteNumbers(t *testing.T) {
	for _, value := range []string{".nan", ".inf", "-.inf"} {
		t.Run(value, func(t *testing.T) {
			requireV8YAMLError(t, []byte("config_version: 8\nvalue: "+value+"\n"), V8YAMLErrorScalarInvalid)
		})
	}
}

func requireV8YAMLError(t *testing.T, source []byte, code V8YAMLErrorCode) *V8YAMLError {
	t.Helper()
	_, err := ParseV8YAML("config.yaml", source)
	if err == nil {
		t.Fatalf("ParseV8YAML succeeded, want %s", code)
	}
	var parseErr *V8YAMLError
	if !errors.As(err, &parseErr) {
		t.Fatalf("error = %T, want *V8YAMLError: %v", err, err)
	}
	if parseErr.Code != code {
		t.Fatalf("Code = %q, want %q: %v", parseErr.Code, code, parseErr)
	}
	if parseErr.Source != "config.yaml" || parseErr.Summary == "" || parseErr.Action == "" {
		t.Fatalf("error lacks source/summary/action: %#v", parseErr)
	}
	return parseErr
}

func nestedV8YAML(containerCount int) string {
	return "config_version: 8\nnested: " + strings.Repeat("{value: ", containerCount) +
		"true" + strings.Repeat("}", containerCount) + "\n"
}

func sequenceV8YAML(items int) string {
	var source strings.Builder
	source.Grow(32 + items*4)
	source.WriteString("config_version: 8\nitems:\n")
	for range items {
		source.WriteString("- 0\n")
	}
	return source.String()
}

func repeatedByte(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
