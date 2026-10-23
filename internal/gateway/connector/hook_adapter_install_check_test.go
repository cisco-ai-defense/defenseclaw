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

// The two per-user Windows adapters carry the same install check, and only
// a per-user render in fail mode open has it (a closed render is closed
// already; a managed render follows administrator policy, not the per-user
// lock), so the managed and closed renders are unchanged (GAP-0915).
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
	copilot := adapterInstallCheck(render("copilot-hook.ps1", "open", false))
	cursor := adapterInstallCheck(render("cursor-hook.ps1", "open", false))
	if copilot == "" || cursor == "" {
		t.Fatalf("an open per-user adapter has no install check (copilot %v, cursor %v)", copilot != "", cursor != "")
	}
	if copilot != cursor {
		t.Fatalf("the adapters' install checks differ:\n%s\n---\n%s", copilot, cursor)
	}
	for _, adapter := range []string{"copilot-hook.ps1", "cursor-hook.ps1"} {
		open := render(adapter, "open", false)
		if strings.Count(open, "Test-DefenseClawInstallLockHeld") != 2 {
			t.Errorf("%s: the open per-user catch block does not read the install check exactly once", adapter)
		}
		for _, other := range []struct {
			mode    string
			managed bool
		}{{"closed", false}, {"open", true}, {"closed", true}} {
			if strings.Contains(render(adapter, other.mode, other.managed), "Test-DefenseClawInstallLockHeld") {
				t.Errorf("%s rendered %s (managed %v) carries the per-user install check", adapter, other.mode, other.managed)
			}
		}
	}
}
