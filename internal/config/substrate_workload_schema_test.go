// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigSchemaWorkloadSubjectPatternMatchesTheGoRule: the config JSON
// schema carries the workload subject rule in two places (the profile match
// workloads and the OIDC subject). Both must be the Go rule exactly, or an
// editor that validates against the schema accepts a subject such as repo:*
// that the gateway refuses at load (GAP-0235).
func TestConfigSchemaWorkloadSubjectPatternMatchesTheGoRule(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "config", "v8", "defenseclaw-config.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var patterns []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if p, ok := x["pattern"].(string); ok && strings.Contains(p, "[:/]") && strings.Contains(p, `\*`) {
				patterns = append(patterns, p)
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(doc)
	if len(patterns) != 2 {
		t.Fatalf("the schema has %d workload subject patterns, want 2: %q", len(patterns), patterns)
	}
	for _, p := range patterns {
		if p != substrateWorkloadSubjectRe.String() {
			t.Errorf("schema pattern %q is not the Go rule %q", p, substrateWorkloadSubjectRe.String())
		}
	}
}
