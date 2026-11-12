// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"runtime"
	"testing"
)

// The 1.0.9 review of GAP-0534 (r11 S1) read ShellParseBound as skipping the
// relative-cwd and empty-home guard that actionPosixCommandDecision applies
// first, so that a per-user gateway would grade a recovered-parse call the
// hook client sends no reason for. UnprovenProtectedWrite applies the same
// guard, so the two readings agree: this pins that ShellParseBound is the
// client reading (ActionCommandAuditReasonWithDialect is "shell-parse-bound")
// for every cwd and home, and is false for a relative or empty cwd and for an
// empty home.
func TestShellParseBoundIsTheClientReadingForEveryCwdAndHome(t *testing.T) {
	home := t.TempDir()
	const (
		ordinary = `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/project/output`
		form     = `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/.defenseclaw`
		benign   = "Get-ChildItem -Name"
	)
	homes := []string{home, "", `C:\Users\u1`}
	cwds := map[string][]string{
		home:          {filepath.Join(home, "project"), "project", "./project", ""},
		"":            {filepath.Join(home, "project"), "project", ""},
		`C:\Users\u1`: {`C:\Users\u1\project`, `project`, ""},
	}
	sawBound := false
	for _, connector := range []string{"claudecode", "codex"} {
		for _, tool := range []string{"Bash", "PowerShell", "exec_command"} {
			dialect := hookShellDialect(connector, tool)
			for _, h := range homes {
				for _, cwd := range cwds[h] {
					for _, command := range []string{ordinary, form, benign} {
						got := ShellParseBound(connector, tool, command, cwd, h)
						want := ActionCommandAuditReasonWithDialect(command, cwd, h, dialect) == "shell-parse-bound"
						if got != want {
							t.Errorf("%s/%s home=%q cwd=%q %q: ShellParseBound=%v, client reading bound=%v",
								connector, tool, h, cwd, command, got, want)
						}
						if got && (h == "" || !filepath.IsAbs(cwd)) {
							t.Errorf("%s/%s home=%q cwd=%q %q: bound without an absolute cwd and a home",
								connector, tool, h, cwd, command)
						}
						sawBound = sawBound || got
					}
				}
			}
		}
	}
	if runtime.GOOS != "windows" && !sawBound {
		t.Fatal("no case read as shell-parse-bound; the corpus no longer reaches the bound")
	}
}
