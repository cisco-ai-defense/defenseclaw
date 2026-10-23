// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0326: a Claude Code PreCompact policy block arrives as decision block,
// the shape the gateway renders for that event. The hook passes it to Claude
// Code (exit 0, the block on stdout) as it does for UserPromptSubmit, in
// both fail modes, and logs no failure. An allow-shaped native answer beside
// a block action is still refused.
func TestClaudeCodePreCompactPolicyBlockReachesTheAgent(t *testing.T) {
	const block = `{"action":"block","reason":"policy reason","claude_code_output":{"decision":"block","reason":"policy reason"}}`
	for _, mode := range []string{"closed", "open"} {
		for _, event := range []string{"PreCompact", "UserPromptSubmit"} {
			var home string
			r := run(t, "claudecode", ok(block), func(o *Options) {
				o.FailMode = mode
				o.Event = event
				home = o.Home
			})
			log, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
			if r.code != 0 || !strings.Contains(r.stdout, `"decision":"block"`) || len(log) != 0 {
				t.Errorf("%s %s: code=%d stdout=%q stderr=%q failures=%q, want the policy block passed on",
					mode, event, r.code, r.stdout, r.stderr, log)
			}
		}
	}
	contradicting := `{"action":"block","reason":"policy reason","claude_code_output":{"decision":"approve"}}`
	r := run(t, "claudecode", ok(contradicting), func(o *Options) {
		o.FailMode = "closed"
		o.Event = "PreCompact"
	})
	if r.code == 0 {
		t.Errorf("an approve beside a block action: code=%d stdout=%q, want it refused", r.code, r.stdout)
	}
}
