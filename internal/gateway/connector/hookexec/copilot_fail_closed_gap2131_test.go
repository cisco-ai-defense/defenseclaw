// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"strings"
	"testing"
)

const gap2131Prompt = `{"modifiedTransformedPrompt":"DefenseClaw blocked the current user message. Do not answer it or call tools for it. Reply only: `

// GAP-2131: on a gateway outage the native hook answers a Copilot CLI prompt
// (userPromptTransformed) as it answers a Copilot tool call: where the tool
// call is denied (per-user fail mode closed, strict availability, a
// standalone managed hook) the prompt is replaced with DefenseClaw's notice;
// where the tool call runs (per-user fail mode open, the OSS default) the
// prompt passes. Claude Code, Codex, Cursor and Kiro block a prompt in the
// same cases. Before the fix the prompt passed on every profile.
func TestGAP2131CopilotPromptOnAnOutageFollowsTheToolCall(t *testing.T) {
	profiles := map[string]func(*Options){
		"per-user":   func(*Options) {},
		"strict":     func(o *Options) { o.StrictAvailability = true },
		"standalone": func(o *Options) { o.ManagedEnterprise = true },
	}
	for name, profile := range profiles {
		for _, mode := range []string{"open", "closed"} {
			outcome := func(event, stdin string) runResult {
				return run(t, "copilot", &stubRT{err: errors.New("dial tcp: connection refused")}, func(o *Options) {
					profile(o)
					o.Event, o.FailMode, o.Stdin = event, mode, strings.NewReader(stdin)
				})
			}
			tool := outcome("preToolUse", `{"toolName":"bash","toolArgs":"{}"}`)
			prompt := outcome("userPromptTransformed", `{"prompt":"hi","transformedPrompt":"hi"}`)
			denied := strings.Contains(tool.stdout, `"permissionDecision":"deny"`)
			replaced := strings.HasPrefix(strings.TrimSpace(prompt.stdout), gap2131Prompt)
			if prompt.code != 0 || replaced != denied {
				t.Errorf("%s %s: prompt code=%d stdout=%q, tool denied=%t; want the prompt replaced exactly when the tool call is denied",
					name, mode, prompt.code, prompt.stdout, denied)
			}
			if replaced && !strings.Contains(prompt.stdout, "DefenseClaw ") {
				t.Errorf("%s %s: replacement %q names no reason", name, mode, prompt.stdout)
			}
			if want := name != "per-user" || mode == "closed"; denied != want {
				t.Errorf("%s %s: tool call denied=%t, want %t (the outage rule)", name, mode, denied, want)
			}
		}
	}
	// The per-user wording is the prompt's, not the tool call's.
	r := run(t, "copilot", &stubRT{err: errors.New("dial tcp: connection refused")}, func(o *Options) {
		o.Event, o.FailMode, o.Stdin = "userPromptTransformed", "closed", strings.NewReader(`{"prompt":"hi"}`)
	})
	if !strings.Contains(r.stdout, "DefenseClaw blocked this prompt") || strings.Contains(r.stdout, "this tool call") {
		t.Errorf("per-user closed replacement %q, want it worded for a prompt", r.stdout)
	}
	// Other Copilot prompt events cannot be stopped and stay silent.
	r = run(t, "copilot", &stubRT{err: errors.New("dial tcp: connection refused")}, func(o *Options) {
		o.Event, o.FailMode, o.Stdin = "userPromptSubmitted", "closed", strings.NewReader(`{"prompt":"hi"}`)
	})
	if strings.TrimSpace(r.stdout) != "" {
		t.Errorf("userPromptSubmitted outage stdout %q, want nothing", r.stdout)
	}
}

// GAP-2131: a gateway answer the native hook cannot use, on a Copilot CLI
// prompt, in fail mode closed: the prompt is replaced too.
func TestGAP2131CopilotPromptOnAnUnusableAnswerFailsClosed(t *testing.T) {
	for name, profile := range map[string]func(*Options){"per-user": func(*Options) {}, "standalone": func(o *Options) { o.ManagedEnterprise = true }} {
		r := run(t, "copilot", &stubRT{status: 500, body: "boom"}, func(o *Options) {
			profile(o)
			o.Event, o.FailMode, o.Stdin = "userPromptTransformed", "closed", strings.NewReader(`{"prompt":"hi"}`)
		})
		if r.code != 0 || !strings.HasPrefix(strings.TrimSpace(r.stdout), gap2131Prompt) {
			t.Errorf("%s HTTP 500: code=%d stdout=%q stderr=%q, want the prompt replaced", name, r.code, r.stdout, r.stderr)
		}
	}
}

// GAP-2130 (native hook side, unchanged): a block of a tool call without its
// native deny is refused in fail mode open too.
func TestGAP2130CopilotNativeHookRefusesABlockWithoutItsDenyInOpenMode(t *testing.T) {
	for _, body := range []string{`{"action":"block","raw_action":"block","hook_output":{}}`, `{"action":"block","raw_action":"block"}`,
		`{"action":"block","raw_action":"block","hook_output":{"permissionDecision":"allow"}}`} {
		r := run(t, "copilot", ok(body), func(o *Options) { o.FailMode = "open" })
		if r.code != 0 || !strings.Contains(r.stdout, `"permissionDecision":"deny"`) {
			t.Errorf("%s: code=%d stdout=%q, want the native deny", body, r.code, r.stdout)
		}
	}
}
