// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// GAP-1730: the native hook forwards the gateway's replacement of a blocked
// Copilot prompt on every profile.
func TestGAP1730CopilotNativeHookForwardsTheBlockedPromptReplacement(t *testing.T) {
	const notice = "DefenseClaw blocked the current user message. Reply only: blocked."
	replaced := `{"action":"block","raw_action":"block","hook_output":{"modifiedTransformedPrompt":"` + notice + `"}}`
	profiles := map[string]func(*Options){
		"per-user":           func(*Options) {},
		"standalone managed": func(opts *Options) { opts.ManagedEnterprise = true },
		"secure client":      func(opts *Options) { opts.ManagedEnterprise = true; opts.SecureClient = true },
	}
	for name, profile := range profiles {
		for _, mode := range []string{"open", "closed"} {
			result := run(t, "copilot", ok(replaced), func(opts *Options) {
				profile(opts)
				opts.Event = "userPromptTransformed"
				opts.FailMode = mode
			})
			if result.code != 0 || strings.TrimSpace(result.stdout) != `{"modifiedTransformedPrompt":"`+notice+`"}` {
				t.Fatalf("%s %s: code=%d stdout=%q stderr=%q, want the replaced prompt", name, mode, result.code, result.stdout, result.stderr)
			}
		}
	}
}

// GAP-1752: a gateway block of a Copilot CLI prompt that carries no
// replacement (an empty, missing or other hook output) still stops the
// prompt: the native hook writes DefenseClaw's generic replacement, on the
// per-user and the standalone managed profile, in both fail modes (a
// contradictory answer is no outage). Before the fix it wrote only an error
// line and no output, which Copilot reads as no modification, so the blocked
// prompt reached the model.
func TestGAP1752CopilotPromptBlockWithoutReplacementFailsClosed(t *testing.T) {
	// CopilotBlockedPromptText, written out so the test also runs before it existed.
	want := `{"modifiedTransformedPrompt":"DefenseClaw blocked the current user message. Do not answer it or call tools for it. ` +
		`Reply only: DefenseClaw blocked this prompt under the configured security policy."}`
	bodies := map[string]string{
		"empty output": `{"action":"block","raw_action":"block","hook_output":{}}`,
		"no output":    `{"action":"block","raw_action":"block"}`,
		"empty prompt": `{"action":"block","raw_action":"block","hook_output":{"modifiedTransformedPrompt":""}}`,
		"other field":  `{"action":"block","raw_action":"block","hook_output":{"additionalContext":"x"}}`,
		"non-string":   `{"action":"block","raw_action":"block","hook_output":{"modifiedTransformedPrompt":7}}`,
	}
	profiles := map[string]func(*Options){
		"per-user":           func(*Options) {},
		"standalone managed": func(opts *Options) { opts.ManagedEnterprise = true },
	}
	for profileName, profile := range profiles {
		for bodyName, body := range bodies {
			for _, mode := range []string{"open", "closed"} {
				result := run(t, "copilot", ok(body), func(opts *Options) {
					profile(opts)
					opts.Event = "userPromptTransformed"
					opts.FailMode = mode
				})
				if result.code != 0 || strings.TrimSpace(result.stdout) != want {
					t.Errorf("%s %s %s: code=%d stdout=%q stderr=%q, want exit 0 and %s",
						profileName, bodyName, mode, result.code, result.stdout, result.stderr, want)
				}
			}
		}
	}
}
