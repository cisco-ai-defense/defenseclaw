// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestDefaultYAMLDataJSONParity_OverlappingKeys verifies that the
// bundled policies/default.yaml and policies/rego/data.json agree on
// every field they both define.
//
// Context: the gateway reads policies/rego/data.json at startup
// (loadStore in engine.go) — the YAML is documentation / what
// `defenseclaw policy show default` displays. A silent drift between
// the two (e.g. data.json adding scanner_overrides.mcp without a
// matching YAML edit) means the operator sees a policy that doesn't
// match what the gateway is enforcing, which is exactly what burned
// us before this test existed.
//
// The fields compared are the intersection of the two files. Keys
// that exist only in YAML (admission, skill_actions, firewall, ...)
// or only in data.json (severity_ranking, config, actions) are
// intentionally not compared: they live in only one source by design.
func TestDefaultYAMLDataJSONParity_OverlappingKeys(t *testing.T) {
	_, selfPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	repoRoot := filepath.Join(filepath.Dir(selfPath), "..", "..")

	yamlPath := filepath.Join(repoRoot, "policies", "default.yaml")
	jsonPath := filepath.Join(repoRoot, "policies", "rego", "data.json")

	yamlBytes, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("read default.yaml: %v", err)
	}
	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read data.json: %v", err)
	}

	var yamlData map[string]any
	if err := yaml.Unmarshal(yamlBytes, &yamlData); err != nil {
		t.Fatalf("parse default.yaml: %v", err)
	}
	var jsonData map[string]any
	if err := json.Unmarshal(jsonBytes, &jsonData); err != nil {
		t.Fatalf("parse data.json: %v", err)
	}

	// Compare overlapping top-level keys. Skip leaf-only keys that
	// belong to one source by design.
	overlap := []string{"scanner_overrides", "first_party_allow_list"}
	for _, k := range overlap {
		k := k
		t.Run(k, func(t *testing.T) {
			a := canonicalize(yamlData[k])
			b := canonicalize(jsonData[k])
			if !reflect.DeepEqual(a, b) {
				t.Errorf("drift on top-level key %q\n  yaml: %#v\n  json: %#v", k, a, b)
			}
		})
	}

	// Compare guardrail.patterns by family.
	t.Run("guardrail.patterns", func(t *testing.T) {
		yg, _ := yamlData["guardrail"].(map[string]any)
		jg, _ := jsonData["guardrail"].(map[string]any)
		yp, _ := yg["patterns"].(map[string]any)
		jp, _ := jg["patterns"].(map[string]any)
		for _, family := range []string{"injection", "secrets", "exfiltration"} {
			a := canonicalize(yp[family])
			b := canonicalize(jp[family])
			if !reflect.DeepEqual(a, b) {
				t.Errorf("drift on guardrail.patterns.%s\n  yaml: %#v\n  json: %#v", family, a, b)
			}
		}
	})
}

// canonicalize normalizes the value shapes produced by the YAML and
// JSON decoders so deep-equality is meaningful.
//
// gopkg.in/yaml.v3 returns map[string]any for mappings (matching
// encoding/json) but produces []any for sequences with each element
// at its native YAML type. encoding/json also produces []any for
// arrays. The differences in practice are:
//
//   - numbers: yaml.v3 returns int for unquoted integers, json
//     returns float64. We coerce numeric leaves to float64 here so
//     equality is well-defined.
//   - maps with mixed scalar keys: yaml.v3 with non-string keys
//     returns map[any]any; defaults in our policy files use string
//     keys exclusively, so we don't need to handle that case.
func canonicalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = canonicalize(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = canonicalize(vv)
		}
		return out
	case int:
		return float64(x)
	case int64:
		return float64(x)
	default:
		return v
	}
}
