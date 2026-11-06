// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build regressioncorpora

package gateway

import (
	"fmt"
	"strings"
	"testing"
)

func TestRVWL4TokenNeighbors(t *testing.T) {
	rows := []struct{ name, body string }{
		{"sub-word", "Write-Output $(a\"b\"#); __TAIL__"},
		{"sub-dot", "Write-Output $(.\\a\"b\"#); __TAIL__"},
		{"sub-root", "Write-Output $(\\a\"b\"#); __TAIL__"},
		{"sub-tilde", "Write-Output $(~\\a\"b\"#); __TAIL__"},
		{"sub-slash", "Write-Output $(/a\"b\"#); __TAIL__"},
		{"sub-dash", "Write-Output $(-a\"b\"#); __TAIL__"},
		{"sub-star", "Write-Output $(*a\"b\"#); __TAIL__"},
		{"sub-percent", "Write-Output $(%a\"b\"#); __TAIL__"},
		{"sub-bang", "Write-Output $(!a\"b\"#); __TAIL__"},
		{"sub-question", "Write-Output $(?a\"b\"#); __TAIL__"},
		{"sub-equals", "Write-Output $(=a\"b\"#); __TAIL__"},
		{"sub-underscore", "Write-Output $(_a\"b\"#); __TAIL__"},
		{"sub-digit", "Write-Output $(1a\"b\"#); __TAIL__"},
		{"sub-hex", "Write-Output $(0x1\"b\"#); __TAIL__"},
		{"sub-unicode", "Write-Output $(\u03a3\"b\"#); __TAIL__"},
		{"arr-word", "Write-Output @(a\"b\"#); __TAIL__"},
		{"arr-dot", "Write-Output @(.\\a\"b\"#); __TAIL__"},
		{"arr-root", "Write-Output @(\\a\"b\"#); __TAIL__"},
		{"arr-tilde", "Write-Output @(~\\a\"b\"#); __TAIL__"},
		{"arr-slash", "Write-Output @(/a\"b\"#); __TAIL__"},
		{"arr-dash", "Write-Output @(-a\"b\"#); __TAIL__"},
		{"arr-star", "Write-Output @(*a\"b\"#); __TAIL__"},
		{"arr-percent", "Write-Output @(%a\"b\"#); __TAIL__"},
		{"arr-bang", "Write-Output @(!a\"b\"#); __TAIL__"},
		{"arr-question", "Write-Output @(?a\"b\"#); __TAIL__"},
		{"arr-equals", "Write-Output @(=a\"b\"#); __TAIL__"},
		{"arr-underscore", "Write-Output @(_a\"b\"#); __TAIL__"},
		{"arr-digit", "Write-Output @(1a\"b\"#); __TAIL__"},
		{"arr-hex", "Write-Output @(0x1\"b\"#); __TAIL__"},
		{"arr-unicode", "Write-Output @(\u03a3\"b\"#); __TAIL__"},
		{"paren-word", "Write-Output (a\"b\"#); __TAIL__"},
		{"paren-dot", "Write-Output (.\\a\"b\"#); __TAIL__"},
		{"paren-root", "Write-Output (\\a\"b\"#); __TAIL__"},
		{"paren-tilde", "Write-Output (~\\a\"b\"#); __TAIL__"},
		{"paren-slash", "Write-Output (/a\"b\"#); __TAIL__"},
		{"paren-dash", "Write-Output (-a\"b\"#); __TAIL__"},
		{"paren-star", "Write-Output (*a\"b\"#); __TAIL__"},
		{"paren-percent", "Write-Output (%a\"b\"#); __TAIL__"},
		{"paren-bang", "Write-Output (!a\"b\"#); __TAIL__"},
		{"paren-question", "Write-Output (?a\"b\"#); __TAIL__"},
		{"paren-equals", "Write-Output (=a\"b\"#); __TAIL__"},
		{"paren-underscore", "Write-Output (_a\"b\"#); __TAIL__"},
		{"paren-digit", "Write-Output (1a\"b\"#); __TAIL__"},
		{"paren-hex", "Write-Output (0x1\"b\"#); __TAIL__"},
		{"paren-unicode", "Write-Output (\u03a3\"b\"#); __TAIL__"},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, tail := range rvwlTails() {
				tailAction, _ := rvwlJudge(connector, managed, tail.command)
				for _, row := range rows {
					action, ids := rvwlJudge(connector, managed, strings.Replace(row.body, "__TAIL__", tail.command, 1))
					t.Logf("TOKEN %s %t %s %s action=%s ids=%v", connector, managed, row.name, tail.name, action, ids)
					if action != tailAction {
						t.Errorf("%s", fmt.Sprintf("%s %t %s %s got=%s want=%s", connector, managed, row.name, tail.name, action, tailAction))
					}
				}
			}
		}
	}
}
