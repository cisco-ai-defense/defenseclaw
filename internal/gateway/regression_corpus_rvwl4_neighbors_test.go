// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build regressioncorpora

package gateway

import (
	"fmt"
	"strings"
	"testing"
)

func TestRVWL4Neighbors(t *testing.T) {
	rows := []struct {
		name, body string
		executable bool
	}{
		{"sub-dot-path", "Write-Output $(.\\a[1]#); __TAIL__", true},
		{"sub-root-path", "Write-Output $(\\a[1]#); __TAIL__", true},
		{"sub-tilde-path", "Write-Output $(~\\a[1]#); __TAIL__", true},
		{"sub-sq-glued", "Write-Output $(a'b'#); __TAIL__", true},
		{"sub-dq-var-glued", "Write-Output $(a\"$x\"#); __TAIL__", true},
		{"sub-bracket-glued", "Write-Output $(a[1]#); __TAIL__", true},
		{"sub-block-glued", "Write-Output $(a\"b\"<#x#>); __TAIL__", true},
		{"arr-sq-glued", "Write-Output @(a'b'#); __TAIL__", true},
		{"sb-dq-glued", "& {a\"b\"#}; __TAIL__", true},
		{"sub-after-semicolon", "Write-Output $(1; a\"b\"#); __TAIL__", true},
		{"sub-after-pipe", "Write-Output $(1 | a\"b\"#); __TAIL__", true},
		{"sub-after-call", "Write-Output $(& .\\a[1]#); __TAIL__", true},
		{"sub-after-newline", "Write-Output $(1\na\"b\"#); __TAIL__", true},
		{"sub-type-inert", "Write-Output $([int]# ; __TAIL__\n); Write-Output ok", false},
		{"ss-int-inert", "[int]#; __TAIL__", false},
		{"ss-qualified-type-inert", "[System.Int32]#; __TAIL__", false},
		{"ss-array-type-inert", "[int[]]#; __TAIL__", false},
		{"ss-number-inert", "1#; __TAIL__", false},
		{"ss-variable-inert", "$x#; __TAIL__", false},
		{"ss-paren-inert", "(1)#; __TAIL__", false},
		{"ss-sq-inert", "'a'#; __TAIL__", false},
		{"ss-dq-inert", "\"a\"#; __TAIL__", false},
		{"ss-path-hash-exec", ".\\a[1]#; __TAIL__", true},
		{"ss-path-block-exec", ".\\a[1]<#x#>; __TAIL__", true},
		{"ss-word-block-exec", "a\"b\"<#x#>; __TAIL__", true},
		{"ss-flag-hash-inert", "-1#; __TAIL__", false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, tail := range rvwlTails() {
				tailAction, _ := rvwlJudge(connector, managed, tail.command)
				for _, row := range rows {
					command := strings.Replace(row.body, "__TAIL__", tail.command, 1)
					action, ids := rvwlJudge(connector, managed, command)
					t.Logf("NEIGHBOR %s %t %s %s %s ids=%v", connector, managed, row.name, tail.name, action, ids)
					if row.executable && action != tailAction {
						t.Errorf("%s", fmt.Sprintf("executable %s %t %s %s action=%s want=%s", connector, managed, row.name, tail.name, action, tailAction))
					}
				}
			}
		}
	}
}
