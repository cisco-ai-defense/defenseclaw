// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveRegoDir_PrefersNestedRegoSubdirectory pins the precedence of
// resolveRegoDir against the regression that produced "HILT only triggers at
// tool call time, never at the prompt stage".
//
// Repro shape on disk (matches what older installers left behind):
//
//	<policyDir>/                 ← stale flat layout from ≤0.3.x
//	  guardrail.rego             ← no `confirm` branch, no `_hilt_*` rules
//	  data.json                  ← old block_threshold, no hilt block
//	<policyDir>/rego/            ← canonical layout from ≥0.4.x
//	  guardrail.rego             ← includes confirm + _hilt_* logic
//	  data.json                  ← block_threshold=4, hilt.enabled=true
//
// The previous resolveRegoDir preferred <policyDir>/ first, so the loader
// compiled the stale modules while reading the new data.json via the
// readDataJSON fallback. The verdict for a HIGH finding came back as
// "alert" — there was no confirm branch in the compiled module — and the
// gateway never asked the operator for HILT approval before forwarding the
// prompt to the LLM. Tool-call time still asked because that path runs
// through a separate, non-Rego decision tree.
//
// The fix: always prefer the nested rego/ subdirectory when it exists.
// This test would fail under the old ordering.
func TestResolveRegoDir_PrefersNestedRegoSubdirectory(t *testing.T) {
	parent := t.TempDir()
	nested := filepath.Join(parent, "rego")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}

	// A tiny module at the parent that, if compiled, would override the
	// nested module's `marker` value. We pick a unique attribute name
	// rather than guardrail's `action` chain so this test stays decoupled
	// from any future change to guardrail.rego's surface.
	flatModule := `package defenseclaw.guardrail

import rego.v1

marker := "stale-flat-layout"
`
	nestedModule := `package defenseclaw.guardrail

import rego.v1

marker := "canonical-nested-layout"
`
	if err := os.WriteFile(filepath.Join(parent, "guardrail.rego"), []byte(flatModule), 0o644); err != nil {
		t.Fatalf("write flat module: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "guardrail.rego"), []byte(nestedModule), 0o644); err != nil {
		t.Fatalf("write nested module: %v", err)
	}

	// Both layers carry their own data.json. resolveRegoDir's choice
	// determines which one wins via readDataJSON's lookup order.
	flatData := map[string]interface{}{"layer": "flat"}
	nestedData := map[string]interface{}{"layer": "nested"}
	mustWriteJSON(t, filepath.Join(parent, "data.json"), flatData)
	mustWriteJSON(t, filepath.Join(nested, "data.json"), nestedData)

	got := resolveRegoDir(parent)
	if got != nested {
		t.Fatalf("resolveRegoDir(%q) = %q, want %q (nested rego/ subdir must win when both layouts coexist)", parent, got, nested)
	}
}

// TestResolveRegoDir_HonorsFlatLayoutWhenNoNestedSubdir keeps single-layout
// installs and existing unit tests (which drop .rego files directly into
// t.TempDir()) working. Without this case, the precedence flip would
// silently break callers that intentionally use the flat layout.
func TestResolveRegoDir_HonorsFlatLayoutWhenNoNestedSubdir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "guardrail.rego"), []byte("package x\n"), 0o644); err != nil {
		t.Fatalf("write flat module: %v", err)
	}

	got := resolveRegoDir(dir)
	if got != dir {
		t.Fatalf("resolveRegoDir(%q) = %q, want %q (flat layout must still resolve when no rego/ subdir exists)", dir, got, dir)
	}
}

// TestResolveRegoDir_FallbackOnEmptyDir guards the path where neither
// layout contains .rego files. policy.New() then surfaces a load error —
// verifying that path here keeps the fallback contract obvious.
func TestResolveRegoDir_FallbackOnEmptyDir(t *testing.T) {
	dir := t.TempDir()
	got := resolveRegoDir(dir)
	if got != dir {
		t.Fatalf("resolveRegoDir(%q) = %q, want %q (no .rego files anywhere → return input dir unchanged)", dir, got, dir)
	}
}

func TestResolveRegoDir_FailsClosedOnInvalidCanonicalPath(t *testing.T) {
	dir := t.TempDir()
	canonical := filepath.Join(dir, "rego")
	if err := os.WriteFile(canonical, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write invalid canonical path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "legacy.rego"), []byte("package legacy\n"), 0o600); err != nil {
		t.Fatalf("write legacy module: %v", err)
	}
	mustWriteJSON(t, filepath.Join(dir, "data.json"), map[string]interface{}{})

	if got := resolveRegoDir(dir); got != canonical {
		t.Fatalf("resolveRegoDir(%q) = %q, want invalid canonical path %q", dir, got, canonical)
	}
	if _, err := New(dir); err == nil {
		t.Fatal("policy.New downgraded from invalid canonical path to legacy flat policy")
	}
}

// TestNew_LoadsCanonicalNestedLayoutEndToEnd is the integration-shaped
// counterpart to the unit test above: it exercises the full policy.New →
// readDataJSON → store load chain, so we'd catch a regression where a
// future refactor splits resolveRegoDir from readDataJSON's lookup order
// and reintroduces the silent layout-mix bug.
func TestNew_LoadsCanonicalNestedLayoutEndToEnd(t *testing.T) {
	parent := t.TempDir()
	nested := filepath.Join(parent, "rego")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}

	// A self-contained guardrail module shaped like a minimal real policy.
	// We only need enough surface to evaluate `data.guardrail.layer`
	// through the loaded store; this avoids depending on the production
	// guardrail.rego whose surface is allowed to evolve.
	flat := `package defenseclaw.guardrail

import rego.v1

layer := data.guardrail.layer
`
	nestedModule := flat // identical module so the differentiator is data.guardrail.layer

	if err := os.WriteFile(filepath.Join(parent, "guardrail.rego"), []byte(flat), 0o644); err != nil {
		t.Fatalf("write flat module: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "guardrail.rego"), []byte(nestedModule), 0o644); err != nil {
		t.Fatalf("write nested module: %v", err)
	}

	mustWriteJSON(t, filepath.Join(parent, "data.json"), map[string]interface{}{
		"guardrail": map[string]interface{}{"layer": "flat"},
	})
	mustWriteJSON(t, filepath.Join(nested, "data.json"), map[string]interface{}{
		"guardrail": map[string]interface{}{"layer": "nested"},
	})

	eng, err := New(parent)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	if eng.RegoDir() != nested {
		t.Fatalf("RegoDir() = %q, want %q", eng.RegoDir(), nested)
	}

	// Spot-check the store: the data.guardrail.layer value the loader
	// surfaces must come from the nested data.json, not the flat one.
	// We query the guardrail package object so the unexported eval()
	// (which insists on a map result) accepts the response.
	res, err := eng.eval(context.Background(), "data.defenseclaw.guardrail", map[string]interface{}{})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if got := res["layer"]; got != "nested" {
		t.Fatalf("data.defenseclaw.guardrail.layer = %v, want %q (loader picked the wrong layout)", got, "nested")
	}
}

func TestEngineTreatsPolicyDirectoryGlobCharactersLiterally(t *testing.T) {
	parent := t.TempDir()
	policyDir := filepath.Join(parent, "policy[literal]")
	sibling := filepath.Join(parent, "policyl")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatalf("create literal policy directory: %v", err)
	}
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatalf("create sibling directory: %v", err)
	}

	module := `package defenseclaw

import rego.v1

admission := {
	"verdict": "allowed",
	"reason": "literal policy directory",
	"file_action": "allow",
	"install_action": "allow",
	"runtime_action": "allow",
}
`
	if err := os.WriteFile(filepath.Join(policyDir, "admission.rego"), []byte(module), 0o600); err != nil {
		t.Fatalf("write literal policy module: %v", err)
	}
	mustWriteJSON(t, filepath.Join(policyDir, "data.json"), map[string]interface{}{})

	outsideModule := filepath.Join(sibling, "outside.rego")
	if err := os.WriteFile(outsideModule, []byte("not valid Rego"), 0o600); err != nil {
		t.Fatalf("write outside module: %v", err)
	}

	engine, err := New(policyDir)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	if err := engine.Compile(); err != nil {
		t.Fatalf("Compile read a sibling matched by policy-root glob characters: %v", err)
	}
	if _, err := os.Stat(outsideModule); err != nil {
		t.Fatalf("outside module was mutated: %v", err)
	}
}

func TestNewExactDoesNotQuarantineInvalidModule(t *testing.T) {
	dir := t.TempDir()
	mustWriteJSON(t, filepath.Join(dir, "data.json"), map[string]interface{}{})
	modulePath := filepath.Join(dir, "invalid.rego")
	if err := os.WriteFile(modulePath, []byte("not valid Rego"), 0o600); err != nil {
		t.Fatalf("write invalid module: %v", err)
	}

	engine, err := NewExact(dir)
	if err != nil {
		t.Fatalf("NewExact: %v", err)
	}
	if err := engine.Compile(); err == nil {
		t.Fatal("Compile accepted invalid module")
	}
	if _, err := os.Stat(modulePath); err != nil {
		t.Fatalf("read-only exact engine mutated invalid module: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".policy_quarantine")); !os.IsNotExist(err) {
		t.Fatalf("read-only exact engine created quarantine directory: %v", err)
	}
}

func TestLoadDataExactMergesSupplementalAndFailsClosed(t *testing.T) {
	t.Run("merge", func(t *testing.T) {
		dir := t.TempDir()
		mustWriteJSON(t, filepath.Join(dir, "data.json"), map[string]interface{}{
			"marker": "base",
			"config": map[string]interface{}{},
		})
		mustWriteJSON(t, filepath.Join(dir, "data-sandbox.json"), map[string]interface{}{
			"marker":   "supplemental",
			"firewall": map[string]interface{}{"default_action": "deny"},
		})

		data, err := LoadDataExact(dir)
		if err != nil {
			t.Fatalf("LoadDataExact: %v", err)
		}
		if data["marker"] != "supplemental" || data["firewall"] == nil || data["config"] == nil {
			t.Fatalf("effective data = %#v", data)
		}
	})

	for _, test := range []struct {
		name string
		file string
		data string
	}{
		{name: "base null", file: "data.json", data: "null"},
		{name: "base array", file: "data.json", data: "[]"},
		{name: "supplemental malformed", file: "data-sandbox.json", data: "{"},
		{name: "supplemental null", file: "data-sandbox.json", data: "null"},
		{name: "supplemental array", file: "data-sandbox.json", data: "[]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			mustWriteJSON(t, filepath.Join(dir, "data.json"), map[string]interface{}{})
			if err := os.WriteFile(filepath.Join(dir, test.file), []byte(test.data), 0o600); err != nil {
				t.Fatalf("write malformed data: %v", err)
			}

			_, err := LoadDataExact(dir)
			if err == nil || !strings.Contains(err.Error(), test.file) {
				t.Fatalf("LoadDataExact error = %v, want %s failure", err, test.file)
			}
		})
	}
}

func mustWriteJSON(t *testing.T, path string, v interface{}) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
