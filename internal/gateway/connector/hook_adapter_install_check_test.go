// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// adapterInstallCheck returns the Test-DefenseClawInstallLockHeld function
// of a rendered adapter, each line without its indentation.
func adapterInstallCheck(body string) string {
	start := strings.Index(body, "function Test-DefenseClawInstallLockHeld {")
	if start < 0 {
		return ""
	}
	indent := 0
	for start-indent-1 >= 0 && body[start-indent-1] == ' ' {
		indent++
	}
	closing := strings.Repeat(" ", indent) + "}"
	var lines []string
	for i, line := range strings.SplitAfter(body[start-indent:], "\n") {
		lines = append(lines, strings.TrimLeft(line, " "))
		if i > 0 && strings.TrimRight(line, "\r\n") == closing {
			return strings.Join(lines, "")
		}
	}
	return ""
}

// The per-user Copilot adapter carries the one install check (GAP-0915) and
// answers an install with its native deny in every fail mode (GAP-0649): its
// open and closed renders read it before the launcher, before writing an
// answer and in the catch block. Cursor's adapter blocks every local failure
// in every mode on this release, so it needs none. A managed render follows
// administrator policy, not the per-user lock, and carries no check.
func TestWindowsAdaptersShareTheOneInstallCheck(t *testing.T) {
	render := func(adapter, failMode string, managed bool) string {
		t.Helper()
		if adapter == "cursor-hook.ps1" {
			body, err := renderWindowsCursorAdapter(`C:\DefenseClaw\defenseclaw-hook.exe`, failMode, managed, 10_000)
			if err != nil {
				t.Fatal(err)
			}
			return string(body)
		}
		tmpl, err := hookFS.ReadFile("hooks/copilot-hook.ps1")
		if err != nil {
			t.Fatal(err)
		}
		body, err := renderTemplate(string(tmpl), templateData{FailMode: failMode, Managed: managed,
			HookBinaryPS: `C:\DefenseClaw\defenseclaw-hook.exe`, CopilotHookTimeoutMS: 10_000})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	open, closed := adapterInstallCheck(render("copilot-hook.ps1", "open", false)), adapterInstallCheck(render("copilot-hook.ps1", "closed", false))
	if open == "" || open != closed {
		t.Fatalf("the per-user Copilot renders do not carry the same install check:\n%s\n---\n%s", open, closed)
	}
	for _, tc := range []struct {
		adapter, mode string
		managed       bool
		// the definition plus each read: since GAP-1372 only a launcher
		// failure reads it; the native hook answers every other call.
		reads int
	}{
		{"copilot-hook.ps1", "open", false, 2}, {"copilot-hook.ps1", "closed", false, 2},
		{"copilot-hook.ps1", "open", true, 0}, {"copilot-hook.ps1", "closed", true, 0},
		{"cursor-hook.ps1", "open", false, 0}, {"cursor-hook.ps1", "closed", false, 0},
		{"cursor-hook.ps1", "open", true, 0}, {"cursor-hook.ps1", "closed", true, 0},
	} {
		if got := strings.Count(render(tc.adapter, tc.mode, tc.managed), "Test-DefenseClawInstallLockHeld"); got != tc.reads {
			t.Errorf("%s rendered %s (managed %v) names the per-user install check %d times, want %d", tc.adapter, tc.mode, tc.managed, got, tc.reads)
		}
	}
}
