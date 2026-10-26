// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"strings"
	"testing"
)

// A standalone administrator's fail mode open applies to gateway outages. A
// gateway that answered block with a native output the agent does not read as
// a denial (another surface's dialect, an allow, or none) is not an outage: the
// managed hook still denies natively, as it does under closed.
func TestManagedOpenBlockWithoutItsNativeDenialStaysClosed(t *testing.T) {
	for _, tc := range []struct {
		name, connector, surface, event, output string
	}{
		{"vscode PreToolUse with the Copilot CLI shape", "copilot", copilotVSCodeLocalSurface, "PreToolUse", `{"permissionDecision":"deny","permissionDecisionReason":"r"}`},
		{"vscode PreToolUse with an allow", "copilot", copilotVSCodeLocalSurface, "PreToolUse", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`},
		{"vscode PreToolUse without output", "copilot", copilotVSCodeLocalSurface, "PreToolUse", ``},
		{"vscode UserPromptSubmit that continues", "copilot", copilotVSCodeLocalSurface, "UserPromptSubmit", `{"continue":true}`},
		{"copilot preToolUse with an allow", "copilot", "", "preToolUse", `{"permissionDecision":"allow"}`},
		{"copilot permissionRequest with an allow", "copilot", "", "permissionRequest", `{"behavior":"allow"}`},
		{"cursor beforeShellExecution with an allow", "cursor", "", "beforeShellExecution", `{"permission":"allow"}`},
		{"cursor beforeSubmitPrompt that continues", "cursor", "", "beforeSubmitPrompt", `{"continue":true}`},
		{"antigravity PreToolUse with an allow", "antigravity", "", "PreToolUse", `{"decision":"allow"}`},
		{"devin PreToolUse with an allow", "devin", "", "PreToolUse", `{"decision":"allow"}`},
		{"kiro PreToolUse with an allow", "kiro", "", "PreToolUse", `{"decision":"allow"}`},
		{"opencode tool.execute.before with an allow", "opencode", "", "tool.execute.before", `{"decision":"allow"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp, found := specFor(tc.connector)
			if !found {
				t.Fatalf("missing %s spec", tc.connector)
			}
			if tc.surface == copilotVSCodeLocalSurface {
				sp = copilotVSCodeLocalSpec
			}
			body := `{"action":"block","reason":"DefenseClaw could not complete its hook check."}`
			if tc.output != "" {
				body = `{"action":"block","reason":"DefenseClaw could not complete its hook check.","hook_output":` + tc.output + `}`
			}
			var stdout, stderr bytes.Buffer
			code := sp.decide(Options{Connector: tc.connector, Event: tc.event, HookSurface: tc.surface,
				ManagedEnterprise: true, ManagedStandalone: true, FailMode: "open",
				Stdout: &stdout, Stderr: &stderr}, []byte(body))
			t.Logf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			if !managedOpenAnswerDenies(sp, tc.event, code, stdout.String()) {
				t.Fatalf("managed open block: code=%d stdout=%q stderr=%q, want the native denial", code, stdout.String(), stderr.String())
			}
		})
	}
}

func managedOpenAnswerDenies(sp spec, event string, code int, stdout string) bool {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	switch sp.style {
	case styleHookEchoDecision, styleHookDecisionStderr:
		// Devin and Kiro read exit 2 as the block.
		return code == blockExit && !strings.Contains(stdout, `"allow"`)
	case stylePluginBridge:
		return strings.Contains(last, `"deny"`) || strings.Contains(last, `"block"`)
	}
	return last != "" && nativeOutputAgrees(sp, event, "block", last)
}
