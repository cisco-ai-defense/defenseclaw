// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// verdictRuleIDs returns the sorted rule IDs of rule findings ("ID:Title")
// in findings and the operator local-pattern flags apart.
func verdictRuleIDs(findings []string) (rules, local []string) {
	for _, f := range findings {
		id, _, ok := strings.Cut(f, ":")
		switch {
		case !ok:
			local = append(local, f)
		case strings.HasPrefix(id, "pii-") || strings.HasPrefix(id, "exfil-") || strings.HasPrefix(id, "bulk-"):
			local = append(local, f)
		default:
			if !slices.Contains(rules, id) {
				rules = append(rules, id)
			}
		}
	}
	slices.Sort(rules)
	return rules, local
}

// TestModelResponseCheckReadsTheHookDetectors is the rel-1-0-10 GAP-0210 /
// GAP-0211 / GAP-0213 property: a model response is decided by the detectors
// that decide a prompt or a tool result on the hook path. Every text case of
// the regex security suite (prompts and completions, attacks and benign
// look-alikes) goes through the completion check the proxy runs (regex_only,
// whole and mid-stream) and through the hook message check; both must report
// the same rule IDs at the same severity. A secret, a PII value, an injected
// instruction or a documentation placeholder therefore reads the same in an
// assistant turn as in a prompt, and a rule change reaches every surface.
func TestModelResponseCheckReadsTheHookDetectors(t *testing.T) {
	cases := readJSONL[regexCase](t, "regex", "corpus.jsonl")
	api := &APIServer{scannerCfg: &config.Config{}}
	insp := NewGuardrailInspector("local", nil, nil)
	insp.SetDetectionStrategy("regex_only", "", "", "", false)
	ctx := context.Background()
	// The secret rule fixtures (rules_test.go) as assistant text too.
	for _, fx := range secretRuleTruePositives() {
		cases = append(cases, regexCase{ID: "secret-fixture/" + fx.name, Direction: "completion", Content: fx.input})
	}
	checked, withFindings := 0, 0
	for _, c := range cases {
		if c.Direction != "prompt" && c.Direction != "completion" {
			continue
		}
		checked++
		for _, hookDirection := range []string{"prompt", "tool_result"} {
			hook := api.inspectMessageContent(ctx, claudeCodeContentInspectRequest(c.Content, hookDirection))
			hookRules, _ := verdictRuleIDs(hook.Findings)
			if hookDirection == "prompt" && len(hookRules) > 0 {
				withFindings++
			}
			whole := insp.Inspect(ctx, "completion", c.Content, nil, "model", "observe")
			mid := insp.InspectMidStream(ctx, "completion", c.Content, []ChatMessage{{Role: "assistant", Content: c.Content}}, "model", "observe")
			for name, v := range map[string]*ScanVerdict{"completion": whole, "mid-stream": mid} {
				respRules, local := verdictRuleIDs(v.Findings)
				if !slices.Equal(respRules, hookRules) {
					t.Errorf("%s: %s rules %v, hook %s rules %v", c.ID, name, respRules, hookDirection, hookRules)
				}
				if len(local) > 0 {
					t.Errorf("%s: %s has detections the hook path does not run: %v", c.ID, name, local)
				}
				if v.Severity != hook.Severity {
					t.Errorf("%s: %s severity %s, hook %s severity %s", c.ID, name, v.Severity, hookDirection, hook.Severity)
				}
			}
		}
	}
	// Both sides empty would pass vacuously: most attack rows must hit.
	if checked < 400 || withFindings < 200 {
		t.Fatalf("checked %d text cases, %d with rule findings; want the whole regex suite (>= 400, >= 200 with findings)", checked, withFindings)
	}
}
