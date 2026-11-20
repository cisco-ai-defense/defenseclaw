// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// argvScriptRows are the four ordinary long scripts of the train review
// (tbrevfp in REVIEW-TBOUNDS.md, generated here the same way): each over
// 4 KiB in all, and want is the verdict of the text form, which the base
// gives the argv form too (fp-head-vs-base.txt).
func argvScriptRows() []struct {
	id, script string
	unknown    bool // the text form is truncated (a code word past 4 KiB)
} {
	var notes, py, files strings.Builder
	for i := 0; i < 150; i++ {
		fmt.Fprintf(&notes, "line %d of an ordinary generated notes file\n", i)
	}
	for i := 0; i < 700; i++ {
		fmt.Fprintf(&py, "print(%d)\n", i)
	}
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&files, " file%d.txt", i)
	}
	return []struct {
		id, script string
		unknown    bool
	}{
		{"heredoc-5k", "cat > notes.txt <<'EOF'\n" + notes.String() + "EOF", false},
		{"for-list-5k", "for f in" + files.String() + `; do wc -l "$f"; done`, false},
		{"commit-msg-5k", "git commit -m '" + strings.Repeat("ordinary commit message text ", 180) + "'", false},
		{"py-c-5k", "python3 -c '\n" + py.String() + "'", true},
	}
}

// TestArgvShellScriptIsReadAsItsText: the Codex shell tool sends every
// command as ["bash", "-lc", SCRIPT]. A script over 4 KiB whose own words are
// all within the bound was truncated in the argv form for its length alone,
// an alert in the default tier and a block in strict, where the same script
// as text is allowed (rel-1-0-10:GAP-0853). The script is read as its text,
// so the argv form equals the text form in all 5 tiers, on the Claude Code
// shell tool and the Codex shell tool: an ordinary script is allowed, and a
// script whose text form is truncated (a code word past 4 KiB) keeps that
// floor. A state write after the script keeps its tier verdict (alert, block in strict).
func TestArgvShellScriptIsReadAsItsText(t *testing.T) {
	env := boundedLaneEnv(t)
	for _, tier := range boundedTestTiers {
		claude := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		codex := gap0589TierAPI(t, "codex", tier.posture, tier.managed, tier.tier)
		codexDecide := func(command any) (string, []string) {
			resp := codex.evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: env.cwd,
				ToolInput: map[string]any{"command": command},
			})
			return resp.Action, resp.Findings
		}
		for _, row := range argvScriptRows() {
			want := bounded.Allow
			if row.unknown {
				want = bounded.Unknown(tier.tier)
			}
			text, findings := boundedDecideClaudeCode(t, claude, env, boundedShellCommand(row.script))
			if got := boundedParse(text); got != want {
				t.Errorf("%s/%s text: action %s, want %s; %v", tier.name, row.id, text, want, findings)
			}
			argv := []any{"bash", "-lc", row.script}
			action, findings := boundedDecideClaudeCode(t, claude, env, boundedLaneCall{tool: "shell", input: map[string]any{"command": argv}})
			if action != text {
				t.Errorf("%s/%s claudecode argv: action %s, the text form %s; %v", tier.name, row.id, action, text, findings)
			}
			if action, findings := codexDecide(argv); action != text {
				t.Errorf("%s/%s codex argv: action %s, the text form %s; %v", tier.name, row.id, action, text, findings)
			}
			seen := []any{"bash", "-lc", row.script + "\n" + boundedShellSeen}
			if action, findings := codexDecide(seen); boundedParse(action) != gap0747StateWriteAction(tier.tier) {
				t.Errorf("%s/%s codex argv with the state write after it: action %s, want %s; %v", tier.name, row.id, action, gap0747StateWriteAction(tier.tier), findings)
			}
		}
	}
}
