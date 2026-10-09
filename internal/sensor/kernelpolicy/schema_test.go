// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

func loadPolicySchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile("testdata/tracingpolicy-v1.7.0.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("tracingpolicy.json", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("tracingpolicy.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func validateYAML(t *testing.T, schema *jsonschema.Schema, data []byte) error {
	t.Helper()
	var generic any
	if err := yaml.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
	asJSON, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(asJSON, &decoded); err != nil {
		t.Fatal(err)
	}
	return schema.Validate(decoded)
}

// Every policy the compiler can render validates against the CRD schema of
// the lowest Tetragon release this build supports (1.7.0), so a field or an
// operator it does not accept cannot ship.
func TestRenderedPoliciesValidateAgainstTheTracingPolicySchema(t *testing.T) {
	schema := loadPolicySchema(t)
	w := newWorld(t, baseTargets)
	roots := w.roots(nativeProc(4001, 1, 100, 1001, aliceClaudeNew), codexProc(4002, 1, 110, 1001), codexProc(5001, 1, 120, 1002))
	var rendered []Policy
	for _, mode := range []PolicyMode{PolicyMonitor, PolicyEnforce} {
		c := w.compile(Input{
			Observe: true, Connect: true, Roots: roots.Roots,
			Controls: &Scope{Mode: mode, UIDs: []int{1001}},
			Burnin:   &Scope{Mode: PolicyMonitor, UIDs: []int{1002}},
		})
		rendered = append(rendered, c.Policies...)
	}
	// And the lint-time variants: binaries only, pids only.
	for _, roots := range [][]Root{nil, roots.Roots} {
		c := w.compile(Input{Controls: &Scope{Mode: PolicyEnforce, UIDs: []int{1001, 1002}}, Roots: roots})
		rendered = append(rendered, c.Policies...)
	}
	families := map[Family]bool{}
	for _, p := range rendered {
		families[p.Family] = true
		if err := validateYAML(t, schema, p.YAML); err != nil {
			t.Errorf("%s does not validate against the Tetragon 1.7.0 TracingPolicy schema: %v\n%s", p.Name, err, p.YAML)
		}
	}
	for _, f := range Families {
		if !families[f] {
			t.Errorf("no %s policy was rendered", f)
		}
	}
	// Every argument filter names a position in its hook's args list
	// (args: [N]) and never Tetragon's argument number (index: N): the
	// file_open hook declares its file, open mode and opener uid all from
	// argument 0, so index: 1 or index: 2 fails to load on Tetragon 1.7.1
	// with "argFilter for unknown index" (GAP-0030). The schema accepts both
	// forms, so this is checked on the rendered text.
	filters := 0
	for _, p := range rendered {
		var doc map[string]any
		if err := yaml.Unmarshal(stripComments(p.YAML), &doc); err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		spec, _ := doc["spec"].(map[string]any)
		for _, kind := range []string{"lsmhooks", "kprobes"} {
			hooks, _ := spec[kind].([]any)
			for _, h := range hooks {
				hook, _ := h.(map[string]any)
				declared, _ := hook["args"].([]any)
				selectors, _ := hook["selectors"].([]any)
				for _, s := range selectors {
					selector, _ := s.(map[string]any)
					matchArgs, _ := selector["matchArgs"].([]any)
					for _, m := range matchArgs {
						filter, _ := m.(map[string]any)
						filters++
						if _, ok := filter["index"]; ok {
							t.Errorf("%s %s: a matchArgs filter uses index: %v", p.Name, kind, filter["index"])
						}
						positions, _ := filter["args"].([]any)
						if len(positions) != 1 {
							t.Errorf("%s %s: matchArgs args %v, want one position", p.Name, kind, filter["args"])
							continue
						}
						if at, ok := positions[0].(int); !ok || at < 0 || at >= len(declared) {
							t.Errorf("%s %s: matchArgs args %v is not one of the hook's %d args", p.Name, kind, positions, len(declared))
						}
					}
				}
			}
		}
	}
	if filters == 0 {
		t.Fatal("test setup: no matchArgs filter rendered")
	}
	// The validator is live: an operator Tetragon does not know is rejected.
	bad := strings.Replace(string(rendered[0].YAML), "operator: Equal", "operator: Resembles", 1)
	if bad == string(rendered[0].YAML) {
		t.Fatal("test setup: nothing replaced")
	}
	if err := validateYAML(t, schema, []byte(bad)); err == nil {
		t.Fatal("the schema accepted an unknown operator")
	}
}
