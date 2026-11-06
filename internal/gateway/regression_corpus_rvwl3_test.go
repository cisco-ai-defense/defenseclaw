// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build regressioncorpora

package gateway

import (
	"strings"
	"testing"
)

func rvwl3Prefixes() []rvwlForm {
	return []rvwlForm{
		{"fmt-dq-hash", "git log --format=\"%h\"#; "},
		{"fmt1-dq-hash", "git log -1 --format=\"%h\"#; "},
		{"fmt-sq-hash", "git log --format='%h'#; "},
		{"commit-m-dq-hash", "git commit -m\"msg\"#; "},
		{"ss-path-rbracket-hash", ".\\a[1]#; "},
		{"gci-path-rbracket-hash", "Get-ChildItem .\\a[1]#; "},
		{"call-path-rbracket-hash", "& .\\a[1]#; "},
		{"wo-type-hash", "Write-Output [int]#; "},
		{"ss-type-hash", "[int]#; "},
		{"ss-dq-glued-hash", "a\"b\"#; "},
		{"wo-dq-glued-hash", "Write-Output a\"b\"#; "},
		{"wo-sq-glued-hash", "Write-Output a'b'#; "},
		{"cmd-dq-glued-hash", "cmd /c echo a\"b\"#; "},
		{"ss-dq-glued-block", "a\"b\"<#x#>; "},
		{"ss-path-rbracket-block", ".\\a[1]<#x#>; "},
		{"wo-type-block", "Write-Output [int]<#x#>; "},
		{"wo-sq-glued-block", "Write-Output a'b'<#x#>; "},
		{"pipe-dq-glued-hash", "Write-Output x | a\"b\"#; "},
		{"andand-fmt-hash", "Write-Output x && git log --format=\"%h\"#; "},
		{"line2-dq-glued-hash", "Write-Output ok\na\"b\"#; "},
		{"tab-dq-glued-hash", "Write-Output\ta\"b\"#; "},
		{"sb-dq-glued-hash", "& { Write-Output a\"b\"#; @@T@@ }"},
		{"paren-rbracket-hash", "Write-Output (Write-Output a]#; @@T@@)"},
		{"if-type-hash", "if (1) { Write-Output [int]#; @@T@@ }"},
		{"dq-dollar-glued-hash", "Write-Output a\"$x\"#; "},
		{"stopparse-andand", "cmd.exe /c echo --% a && "},
		{"stopparse-glued-andand", "cmd.exe /c echo --% a&& "},
		{"stopparse-qandand-andand", "cmd.exe /c echo --% \"a && b\" && "},
		{"ctl wo-sq-only-hash", "Write-Output 'a'#; "},
		{"ctl wo-dq-only-hash", "Write-Output \"a\"#; "},
		{"ctl fmt-space-hash", "git log --format=\"%h\" #; "},
		{"ctl wo-type-space-hash", "Write-Output [int] #; "},
		{"ctl ss-path-space-hash", ".\\a[1] #; "},
		{"ctl wo-rparen-hash", "Write-Output (1)#; "},
		{"ctl dq-only-block-inert", "Write-Output \"a\"<#; @@T@@ #>"},
		{"ctl stopparse-qandand", "cmd.exe /c echo --% \"a && b\"; "},
		{"ctl stopparse-semicolon", "cmd.exe /c echo --% a ; "},
		{"ctl eq-stopparse", "cmd /c echo a=--% ; "},
		{"ctl comma-stopparse", "cmd /c echo a,--% ; "},
		{"ctl none", ""},
	}
}

func TestRVWL3Comment(t *testing.T) {
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			cell := connector + map[bool]string{false: "/per-user", true: "/managed"}[managed]
			for _, tail := range rvwlTails() {
				for _, p := range rvwl3Prefixes() {
					cmd := p.command + tail.command
					if strings.Contains(p.command, "@@T@@") {
						cmd = strings.ReplaceAll(p.command, "@@T@@", tail.command)
					}
					a, ids := rvwlJudge(connector, managed, cmd)
					t.Logf("CMT3 %-20s %-30s %-14s action=%-5s ids=%v", cell, p.name, tail.name, a, ids)
				}
			}
		}
	}
}
