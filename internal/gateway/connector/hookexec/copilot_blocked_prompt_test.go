// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// GAP-1730: the native hook forwards the gateway's replacement of a blocked
// Copilot prompt on every profile, and refuses a userPromptTransformed block
// that carries no replacement (outside Secure Client) instead of letting the
// prompt reach the model as if it were allowed.
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
	for name, profile := range map[string]func(*Options){
		"per-user":           func(*Options) {},
		"standalone managed": func(opts *Options) { opts.ManagedEnterprise = true },
	} {
		result := run(t, "copilot", ok(`{"action":"block","raw_action":"block","hook_output":{}}`), func(opts *Options) {
			profile(opts)
			opts.Event = "userPromptTransformed"
			opts.FailMode = "closed"
		})
		if strings.Contains(result.stdout, "modifiedTransformedPrompt") || strings.TrimSpace(result.stdout) == "{}" ||
			!strings.Contains(result.stderr, "native output contradicts gateway action") {
			t.Fatalf("%s: block without replacement: code=%d stdout=%q stderr=%q, want a refused answer",
				name, result.code, result.stdout, result.stderr)
		}
	}
}
