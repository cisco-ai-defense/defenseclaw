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
	// The validator is live: an operator Tetragon does not know is rejected.
	bad := strings.Replace(string(rendered[0].YAML), "operator: Equal", "operator: Resembles", 1)
	if bad == string(rendered[0].YAML) {
		t.Fatal("test setup: nothing replaced")
	}
	if err := validateYAML(t, schema, []byte(bad)); err == nil {
		t.Fatal("the schema accepted an unknown operator")
	}
}
