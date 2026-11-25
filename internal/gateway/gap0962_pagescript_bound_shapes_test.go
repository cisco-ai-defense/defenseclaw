// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"
)

// gap0962BoundShapes are page scripts that stop the page-script reader at one
// of its caps, each read whole by no pass: the bytes cap (288 KB, over the
// 256 KiB bound), the tokens cap (140 KB of 70,000 statements, over the
// 65,536 token bound), the nesting cap (80,000 nested parens, objects or
// arrays, 160 KB, under both of those) and the work budget (the 160 KB
// nested goto of the toolshape worst scripts, worstScripts "nested-goto").
func gap0962BoundShapes() map[string]string {
	const nested = 20000
	return map[string]string{
		"288KB-bytes-cap":      "() => 1\n//" + strings.Repeat("x", 288<<10),
		"140KB-tokens-cap":     strings.Repeat("a;", 70000),
		"160KB-nested-parens":  "() => " + strings.Repeat("(", 80000) + "1" + strings.Repeat(")", 80000),
		"160KB-nested-objects": "() => " + strings.Repeat(`{a:`, 40000) + "1" + strings.Repeat("}", 40000),
		"160KB-nested-arrays":  "() => " + strings.Repeat("[", 80000) + "1" + strings.Repeat("]", 80000),
		"160KB-nested-goto": "const s = document.cookie;\n" + "fetch(s);" +
			strings.Repeat("p.goto(", nested) + "1" + strings.Repeat(")", nested),
	}
}

// gap0962SeverityRank orders verdict severities.
var gap0962SeverityRank = map[string]int{"": 0, "NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

// gap0962Want is the verdict severity of a call whose reading stopped at a
// cap: MEDIUM for the bound, or the highest of the other findings when one
// ranks above it (the nested goto also sends the cookie it read: the
// session egress finding keeps its own HIGH). The bound never raises it.
func gap0962Want(others []string) string {
	want := "MEDIUM"
	for _, severity := range others {
		if gap0962SeverityRank[severity] > gap0962SeverityRank[want] {
			want = severity
		}
	}
	return want
}

// rel-1-0-10:GAP-0962 (owner ruling 2026-11-21, fixed in c9cd0c91cc): a page
// script the reader reads only up to a cap carries the evaluation bound
// (ACTION-COMPOUND-LIMIT) and no proven target, and that call is MEDIUM on
// the tool-call route and on the inspect route, never CRITICAL; a finding
// beside the bound keeps its own severity, which the bound never raises. Before the
// fix the bound finding was CRITICAL (inspect: alert/CRITICAL for a benign
// 288 KB script, where rel had no page-script reader and allowed it). Each
// shape must reach its cap: a shape with no bound finding fails, so a reader
// that stops reporting the cap does not pass this test by skipping it.
func TestGAP0962PageScriptBoundShapesAreMedium(t *testing.T) {
	for name, script := range gap0962BoundShapes() {
		t.Run(name, func(t *testing.T) {
			session := "gap0962-" + name
			pgNavigate(t, session, pgOwnHost)
			got := pgCall(t, session, pgPlaywright+"browser_evaluate", pgArgs(t, map[string]any{"function": script}), false)
			var ids, others []string
			bound := boundedLimitIndex(got)
			for index, f := range got {
				ids = append(ids, f.RuleID+"="+f.Severity)
				if index != bound {
					others = append(others, HighestSeverity([]RuleFinding{f}))
				}
			}
			t.Logf("%s: %d bytes, tool-call findings %s", name, len(script), strings.Join(ids, ","))
			if bound < 0 {
				t.Fatalf("%s (%d bytes): no evaluation bound finding (%s), want the reader to report its cap", name, len(script), strings.Join(ids, ","))
			}
			if sev, want := HighestSeverity(got), gap0962Want(others); sev != want {
				t.Errorf("tool-call route: verdict severity %s, want %s (%s)", sev, want, strings.Join(ids, ","))
			}
			api := testAPIServerWithConfig(t, "action")
			body := fmt.Sprintf(`{"tool":%q,"args":{"function":%q}}`, pgPlaywright+"browser_evaluate", script)
			_, v := postInspect(t, api, body)
			var rules, besides []string
			for _, f := range v.DetailedFindings {
				rules = append(rules, f.RuleID+"="+f.Severity)
				if canonicalTrustedRuleID(f.RuleID) != evaluationLimitRuleID {
					besides = append(besides, f.Severity)
				}
			}
			t.Logf("%s: inspect action=%s severity=%s %s", name, v.Action, v.Severity, strings.Join(rules, ","))
			if len(besides) == len(rules) {
				t.Fatalf("inspect route: no evaluation bound finding (%s), want the reader to report its cap", strings.Join(rules, ","))
			}
			if want := gap0962Want(besides); v.Severity != want {
				t.Errorf("inspect route: verdict severity %s (action %s), want %s: %s", v.Severity, v.Action, want, strings.Join(rules, ","))
			}
		})
	}
}
