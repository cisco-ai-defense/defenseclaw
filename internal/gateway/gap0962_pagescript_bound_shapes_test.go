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

// gap0962Want is the exact verdict severity of each shape: MEDIUM for the
// bound alone; the nested goto also sends the cookie it read, so its session
// egress finding keeps its own HIGH. A constant, not the highest of the other
// findings, so that a regression raising any finding to CRITICAL fails
// (CHK-FIX1020 N4).
var gap0962Want = map[string]string{
	"288KB-bytes-cap":      "MEDIUM",
	"140KB-tokens-cap":     "MEDIUM",
	"160KB-nested-parens":  "MEDIUM",
	"160KB-nested-objects": "MEDIUM",
	"160KB-nested-arrays":  "MEDIUM",
	"160KB-nested-goto":    "HIGH",
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
			want, ok := gap0962Want[name]
			if !ok {
				t.Fatalf("%s: no expected severity", name)
			}
			var ids []string
			bound := boundedLimitIndex(got)
			for _, f := range got {
				ids = append(ids, f.RuleID+"="+f.Severity)
			}
			t.Logf("%s: %d bytes, tool-call findings %s", name, len(script), strings.Join(ids, ","))
			if bound < 0 {
				t.Fatalf("%s (%d bytes): no evaluation bound finding (%s), want the reader to report its cap", name, len(script), strings.Join(ids, ","))
			}
			if sev := HighestSeverity(got); sev != want {
				t.Errorf("tool-call route: verdict severity %s, want %s (%s)", sev, want, strings.Join(ids, ","))
			}
			api := testAPIServerWithConfig(t, "action")
			body := fmt.Sprintf(`{"tool":%q,"args":{"function":%q}}`, pgPlaywright+"browser_evaluate", script)
			_, v := postInspect(t, api, body)
			var rules []string
			boundSeen := false
			for _, f := range v.DetailedFindings {
				rules = append(rules, f.RuleID+"="+f.Severity)
				boundSeen = boundSeen || canonicalTrustedRuleID(f.RuleID) == evaluationLimitRuleID
			}
			t.Logf("%s: inspect action=%s severity=%s %s", name, v.Action, v.Severity, strings.Join(rules, ","))
			if !boundSeen {
				t.Fatalf("inspect route: no evaluation bound finding (%s), want the reader to report its cap", strings.Join(rules, ","))
			}
			if v.Severity != want {
				t.Errorf("inspect route: verdict severity %s (action %s), want %s: %s", v.Severity, v.Action, want, strings.Join(rules, ","))
			}
		})
	}
}
