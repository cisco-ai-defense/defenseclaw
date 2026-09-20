// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"
)

func TestObservabilityV8EffectiveProvenanceCoversEveryJSONLeaf(t *testing.T) {
	raw := []byte(`config_version: 8
observability:
  defaults:
    collect: {metrics: false}
  buckets:
    model.io:
      collect: {logs: false}
  redaction_profiles:
    custom:
      extends: sensitive
      field_classes: {content: detect}
  destinations:
    - name: galileo
      kind: otlp
      preset: galileo
      endpoint: https://collector.example.test/v1/traces
`)
	compiled, err := ParseCompileObservabilityV8(
		"provenance.yaml",
		raw,
		ObservabilityV8CompileOptions{DefaultDataDir: t.TempDir()},
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := compiled.Plan.Snapshot()
	annotations := make(map[string]ObservabilityV8Provenance)
	baseCount := 0
	for _, provenance := range snapshot.Provenance {
		if provenance.ValuePath == "" {
			baseCount++
			continue
		}
		if provenance.Origin == "compiled-effective" {
			t.Fatalf("effective leaf retained an unexplained provenance fallback: %+v", provenance)
		}
		if provenance.Path == "" || provenance.Origin == "" {
			t.Fatalf("incomplete effective provenance: %+v", provenance)
		}
		if _, duplicate := annotations[provenance.ValuePath]; duplicate {
			t.Fatalf("duplicate effective value_path %q", provenance.ValuePath)
		}
		annotations[provenance.ValuePath] = provenance
	}
	if baseCount == 0 {
		t.Fatal("source/derivation provenance anchors were removed")
	}
	leaves := effectiveLeafPathsForTest(t, snapshot)
	if len(annotations) != len(leaves) {
		t.Fatalf("effective provenance coverage=%d leaves=%d", len(annotations), len(leaves))
	}
	for _, leaf := range leaves {
		if _, ok := annotations[leaf]; !ok {
			t.Errorf("effective leaf %q has no provenance annotation", leaf)
		}
	}

	endpoint := annotations["observability.destinations[1].transport.endpoint"]
	if endpoint.Origin != "source" || endpoint.Source != "provenance.yaml" || endpoint.Line <= 0 || endpoint.Column <= 0 {
		t.Fatalf("endpoint provenance did not retain source location: %+v", endpoint)
	}
	modelLogs := annotations["observability.buckets[4].collect.logs"]
	if modelLogs.Origin != "source" || modelLogs.Source != "provenance.yaml" || modelLogs.Line <= 0 {
		t.Fatalf("bucket leaf provenance did not retain source location: %+v", modelLogs)
	}
	if got := annotations["observability.buckets[4].collect.traces"].Origin; got != "catalog-default" {
		t.Fatalf("field-local inherited trace collection provenance = %q", got)
	}
	if got := annotations["observability.buckets[4].collect.metrics"].Origin; got != "source" {
		t.Fatalf("global metrics collection provenance = %q", got)
	}
	if got := annotations["observability.redaction_profiles[0].name"].Origin; got != "built-in-profile" {
		t.Fatalf("built-in profile provenance = %q", got)
	}
	if got := annotations["observability.buckets[4].bucket"].Origin; got != "catalog-default" {
		t.Fatalf("bucket identity provenance = %q", got)
	}
	for _, valuePath := range []string{
		"observability.destinations[0].name",
		"observability.destinations[0].kind",
		"observability.destinations[0].generated",
	} {
		if got := annotations[valuePath].Origin; got != "generated" {
			t.Fatalf("generated local destination provenance for %s = %q", valuePath, got)
		}
	}
	if got := annotations["observability.resource_attributes"].Origin; got != "compiled-default" {
		t.Fatalf("empty resource attribute provenance = %q", got)
	}
	if got := annotations["observability.warnings"].Origin; got != "compiler-derived" {
		t.Fatalf("empty warning provenance = %q", got)
	}
	for _, provenance := range snapshot.Provenance {
		if provenance.Detail == "hidden" || provenance.Source == "hidden" || provenance.Path == "hidden" {
			t.Fatal("secret entered provenance metadata")
		}
	}
}

func effectiveLeafPathsForTest(t *testing.T, snapshot ObservabilityV8EffectivePlan) []string {
	t.Helper()
	snapshot.Provenance = nil
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	delete(document, "provenance")
	var result []string
	var walk func(any, string)
	walk = func(value any, path string) {
		switch typed := value.(type) {
		case map[string]any:
			if len(typed) == 0 {
				result = append(result, path)
				return
			}
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				walk(typed[key], v8YAMLChildPath(path, key))
			}
		case []any:
			if len(typed) == 0 {
				result = append(result, path)
				return
			}
			for index, item := range typed {
				walk(item, fmt.Sprintf("%s[%d]", path, index))
			}
		default:
			result = append(result, path)
		}
	}
	walk(document, "observability")
	sort.Strings(result)
	return result
}
