// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1315 (s7-rv1257r3 N12): a FileInfo variable re-bound only to the file
// it already is (a copy of itself, $x = $x, or a chain of copies that brings
// in no other file, $y = $x; $x = $y) is still placed there: its open of an
// agent hook config or the DefenseClaw state keeps the write rule of the
// file, as at rel (the state blocked), in every tier. N12c is the control: a
// copy of a variable bound to another file may change which file it is, and
// the protected file it was is the unknown tier, never its write rule
// (rel-1-0-10:GAP-1257). Every open of a project file stays allowed.
func TestGAP1315SameFileRebinds(t *testing.T) {
	rows := []struct {
		id, text string
		same     bool
	}{
		{"N12 self copy open mode only", "$x = Get-Item %s; $x = $x; $x.Open('Open')", true},
		{"N12b copy chain", "$x = Get-Item %s; $y = $x; $x = $y; $x.Open('Open')", true},
		{"N12c copy of another file", "$x = Get-Item %s; $y = Get-Item 'notes.txt'; $x = $y; $x.Open('Open')", false},
	}
	hookRules := []string{agentHookConfigWriteRuleID, agentHookConfigDisableRuleID, "tamper.detector_state_write"}
	hit := func(got string, rules []string) bool {
		for _, rule := range rules {
			if strings.Contains(got, rule) {
				return true
			}
		}
		return false
	}
	checked := 0
	gap1275Handlers(t, func(t *testing.T, pack string, judge func(string) string) {
		home := os.Getenv("HOME")
		for _, row := range rows {
			for _, target := range gap1138Targets() {
				got := judge(gap1257Command(fmt.Sprintf(row.text, "'"+filepath.Join(home, target.rel)+"'")))
				checked++
				action := hookConfigAction(got)
				var problem string
				switch {
				case target.rules == nil:
					if hit(got, hookRules) || pack != "strict" && action != "allow" {
						problem = "want allow with no protected-write rule"
					}
				case row.same:
					if !hit(got, target.rules) || action == "allow" || target.name == "DefenseClaw state" && action != "block" {
						problem = fmt.Sprintf("want the rel rule tier %v (the state blocked)", target.rules)
					}
				default:
					if action == "allow" || !strings.Contains(got, evaluationLimitRuleID) || hit(got, hookRules) {
						problem = fmt.Sprintf("want the unknown tier (%s), no protected-write rule", evaluationLimitRuleID)
					}
				}
				if problem != "" {
					t.Errorf("%s %s: %s: %s\n%.600s", target.name, row.id, action, problem, got)
				}
			}
		}
	})
	t.Logf("cells checked: %d", checked)
}
