// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP2044RefusedPackErrorSaysWhereWhyAndWhatToChange: the error of a
// refused pack (stderr, exit status 1) named the code alone, so an
// integrator reading stderr had no advice (rel-1-0-10:GAP-2044, GitHub #1452,
// GAS GAP-0090). It now names the file, the reason and what to change, in
// text and --json mode; the JSON on stdout keeps its contract.
func TestGAP2044RefusedPackErrorSaysWhereWhyAndWhatToChange(t *testing.T) {
	for _, tc := range []struct {
		name, body, code string
	}{
		{"unknown field", "version: 1\ncategory: command\nunknown_knob: 1\nrules: []\n", "yaml_invalid"},
		{"duplicate rule id", "version: 1\ncategory: command\nrules:\n" +
			"  - {id: GAP2044-DUP, pattern: 'a', title: A, severity: HIGH, confidence: 0.9, tags: [t]}\n" +
			"  - {id: GAP2044-DUP, pattern: 'b', title: B, severity: HIGH, confidence: 0.9, tags: [t]}\n", "duplicate_rule_id"},
	} {
		for _, asJSON := range []bool{false, true} {
			directory := t.TempDir()
			if err := os.MkdirAll(filepath.Join(directory, "rules"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "rules", "commands.yaml"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			previousDir, previousJSON := rulePackValidateDir, rulePackValidateJSON
			previousOutput := rulePackValidateCmd.OutOrStdout()
			rulePackValidateDir, rulePackValidateJSON = directory, asJSON
			output := &strings.Builder{}
			rulePackValidateCmd.SetOut(output)
			err := rulePackValidateCmd.RunE(rulePackValidateCmd, nil)
			rulePackValidateDir, rulePackValidateJSON = previousDir, previousJSON
			rulePackValidateCmd.SetOut(previousOutput)
			where := tc.name
			if asJSON {
				where += " --json"
			}
			if err == nil {
				t.Errorf("%s: the pack was accepted", where)
				continue
			}
			msg := err.Error()
			for _, want := range []string{"[" + tc.code + "]", "rules/commands.yaml", "; to fix: "} {
				if !strings.Contains(msg, want) {
					t.Errorf("%s: error %q does not carry %q", where, msg, want)
				}
			}
			if strings.HasSuffix(msg, "to fix: ") || strings.Contains(msg, "..") {
				t.Errorf("%s: error %q has an empty remedy or a doubled stop", where, msg)
			}
		}
	}
}

// TestGAP2044EveryCodeHasARemedy: every diagnostic code the loader emits maps
// to advice, and the limit codes take the config writer's remedy, so the two
// commands give one answer.
func TestGAP2044EveryCodeHasARemedy(t *testing.T) {
	limits := map[string]bool{"semantic_rule_count_limit": true, "semantic_catalog_cost_limit": true, "rule_count_limit": true}
	for _, code := range strings.Fields(`yaml_invalid yaml_empty yaml_documents duplicate_rule_id duplicate_tool
		duplicate_category duplicate_finding_id duplicate_suppression_id regex pattern_size_limit pattern_count_limit
		file_size_limit aggregate_size_limit file_count_limit tool_count_limit suppression_count_limit category_count_limit
		inventory_limit semantic_rule_count_limit semantic_catalog_cost_limit rule_count_limit semantic_unavailable
		directory_not_found directory_unreadable not_directory file_unreadable inventory_unreadable rulepack_invalid
		internal loader_panic loader_nil embedded_read severity confidence judge version file_type invalid_tiers
		empty_category validation invalid_manifest inventory_unexpected inventory_empty`) {
		remedy := rulePackRemedy(code)
		if remedy == "" {
			t.Errorf("%s: no remedy", code)
		}
		if limits[code] && !strings.Contains(remedy, "select fewer rules") {
			t.Errorf("%s: remedy %q is not the config writer's", code, remedy)
		}
	}
}
