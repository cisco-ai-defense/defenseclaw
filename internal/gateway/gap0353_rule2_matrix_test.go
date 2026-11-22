// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

const g353Missing = "cat: .env.production: No such file or directory"

func g353Pre(cmd string) map[string]interface{} {
	return claudeToolEvent("PreToolUse", "s1", "read-1", cmd)
}

func g353Fail(cmd, text string) map[string]interface{} { return gap0342Fail("s1", "read-1", cmd, text) }

func g353Post(cmd string, response interface{}) map[string]interface{} {
	post := claudeToolResult("PostToolUse", "s1", "read-1")
	post["tool_input"] = map[string]interface{}{"command": cmd}
	delete(post, "tool_response")
	if response != nil {
		post["tool_response"] = response
	}
	return post
}

func g353Std(stdout, stderr string) map[string]interface{} {
	return map[string]interface{}{"stdout": stdout, "stderr": stderr, "interrupted": false, "isImage": false}
}

func g353ReadTool(event string, extra map[string]interface{}) map[string]interface{} {
	ev := map[string]interface{}{"hook_event_name": event, "session_id": "s1", "tool_use_id": "read-1", "tool_name": "Read",
		"tool_input": map[string]interface{}{"file_path": ".env.production"}}
	for k, v := range extra {
		ev[k] = v
	}
	return ev
}

type g353Row struct {
	name  string
	want  string // refused, allowed, log
	steps []gap0348Step
}

func g353Rows() []g353Row {
	c := gap0348Read
	pre := a348(g353Pre(c))
	clear := a348(g353Fail(c, g353Missing))
	clearB := b348(g353Fail(c, g353Missing))
	empty := g353Post(c, g353Std("", ""))
	secret := "API_KEY=canary-1"
	two := "cat .env.production .env.local"
	twoMissing := g353Missing + "\ncat: .env.local: No such file or directory"
	oneRead := "cat .env.production missing.txt"
	interrupted := g353Fail(c, g353Missing)
	interrupted["is_interrupt"] = true
	noResp := g353Post(c, nil)
	noResp["content"] = secret
	forged := g353Post("cat API_KEY=canary-1", "cat: API_KEY=canary-1: No such file or directory")
	shell := func(cmd, text string) []gap0348Step {
		return []gap0348Step{a348(g353Pre(cmd)), a348(g353Fail(cmd, text)), a348(g353Post(cmd, g353Std("", "")))}
	}
	return []g353Row{
		// Rule 2: must chain.
		{"M01 cleared, then stdout secret + stderr naming the operand", "refused", []gap0348Step{pre, clear, a348(g353Post(c, g353Std(secret, g353Missing)))}},
		{"M02 cleared, then content-block array", "refused", []gap0348Step{pre, clear, a348(g353Post(c, []interface{}{map[string]interface{}{"type": "text", "text": secret}}))}},
		{"M03 cleared, then 'Exit code 0' + secret", "refused", []gap0348Step{pre, clear, a348(g353Post(c, "Exit code 0\n"+secret))}},
		{"M04 cleared, then >64 KiB output", "refused", []gap0348Step{pre, clear, a348(g353Post(c, g353Std(strings.Repeat("A", 70000), "")))}},
		{"M05 cleared, then secret line ending in ': No such file or directory'", "refused", []gap0348Step{pre, clear, a348(g353Post(c, g353Std(secret+": No such file or directory", "")))}},
		{"M06 cleared, then 'cat: <secret>: No such file' (not an operand)", "refused", []gap0348Step{pre, clear, a348(g353Post(c, g353Std("cat: "+secret+": No such file or directory", "")))}},
		{"M07 two operands missing (cleared), then printed", "refused", []gap0348Step{a348(g353Pre(two)), a348(g353Fail(two, twoMissing)), a348(g353Post(two, g353Std(secret, "")))}},
		{"M08 cat .env missing.txt: one read, one missing, then empty post", "refused", []gap0348Step{a348(g353Pre(oneRead)),
			a348(g353Fail(oneRead, secret+"\ncat: missing.txt: No such file or directory")), a348(g353Post(oneRead, g353Std("", "")))}},
		{"M09 cat .env missing.txt, .env empty: only the missing error", "refused", []gap0348Step{a348(g353Pre(oneRead)),
			a348(g353Fail(oneRead, "cat: missing.txt: No such file or directory")), a348(g353Post(oneRead, g353Std("", "")))}},
		{"M10 partial read then I/O error", "refused", []gap0348Step{pre, a348(g353Fail(c, secret+"\ncat: .env.production: Input/output error")), a348(empty)}},
		{"M11 stderr names another file, then empty post", "refused", []gap0348Step{pre, a348(g353Fail(c, "cat: other.env: No such file or directory")), a348(empty)}},
		{"M12 empty successful read (first result)", "refused", []gap0348Step{pre, a348(empty)}},
		{"M13 cleared, replay, then printed (third result)", "refused", []gap0348Step{pre, clear, a348(empty), b348(g353Post(c, g353Std(secret, "")))}},
		{"M14 printed, Stop, cleared on B", "refused", []gap0348Step{pre, a348(g353Post(c, g353Std(secret, ""))), a348(gap0348Stop()), clearB}},
		{"M15 cleared on B, Stop, printed on B", "refused", []gap0348Step{pre, clearB, a348(gap0348Stop()), b348(g353Post(c, g353Std(secret, "")))}},
		{"M16 cleared, then duplicate failure that printed on B", "refused", []gap0348Step{pre, clear, b348(g353Fail(c, secret+"\n"+g353Missing))}},
		{"M17 cleared, then nested file.content", "refused", []gap0348Step{pre, clear, a348(g353Post(c, map[string]interface{}{"type": "text", "file": map[string]interface{}{"content": secret}}))}},
		{"M18 Stop between Pre and cleared, then printed on B", "refused", []gap0348Step{pre, a348(gap0348Stop()), clear, b348(g353Post(c, g353Std(secret, "")))}},
		{"M19 GAP-0337 failed read that printed", "refused", []gap0348Step{pre, a348(g353Fail(c, secret))}},
		{"M20 cleared, then success whose stdout is a JSON string holding the secret", "refused", []gap0348Step{pre, clear, a348(g353Post(c, g353Std(`{"k":"`+secret+`"}`, "")))}},
		// Informational: shapes that read nothing or are not real connector shapes.
		{"L01 cleared, then secret in an unlisted top-level key (not a real shape)", "log", []gap0348Step{pre, clear, a348(noResp)}},
		{"L02 cleared, then second result with its own different tool_input (forged)", "log", []gap0348Step{pre, clear, a348(forged)}},
		{"L03 file content is literally the error line", "log", []gap0348Step{pre, clear, a348(g353Post(c, g353Std(g353Missing, "")))}},
		// Rule 2: benign must not chain.
		{"B01 permission denied, then empty post", "allowed", shell(c, "cat: .env.production: Permission denied")},
		{"B02 two operands missing, then empty post", "allowed", shell(two, twoMissing)},
		{"B03 cleared, then post with the error on stderr", "allowed", []gap0348Step{pre, clear, a348(g353Post(c, g353Std("", g353Missing)))}},
		{"B04 interrupted failure, then empty post", "allowed", []gap0348Step{pre, a348(interrupted), a348(empty)}},
		{"B05 cleared on B, empty post on A, Stop, empty post on B", "allowed", []gap0348Step{pre, clearB, a348(empty), a348(gap0348Stop()), b348(empty)}},
		// Benign shapes the proof does not clear (log: compare branch and merge).
		{"N01 cat .env.production 2>/dev/null (no text)", "allowed", shell("cat .env.production 2>/dev/null", "")},
		{"N02 cat .env.production 2>&1", "log", shell("cat .env.production 2>&1", g353Missing)},
		{"N03 head -n 5 .env.production", "log", shell("head -n 5 .env.production", "head: cannot open '.env.production' for reading: No such file or directory")},
		{"N04 cat < .env.production", "log", shell("cat < .env.production", "/bin/bash: line 1: .env.production: No such file or directory")},
		{"N05 F=.env.production; cat $F", "allowed", shell("F=.env.production; cat $F", g353Missing)},
		{"N06 grep API_KEY .env.production", "log", shell("grep API_KEY .env.production", "grep: .env.production: No such file or directory")},
		{"N07 cat .env.production || echo none", "log", shell("cat .env.production || echo none", g353Missing+"\nnone")},
		{"N08 test -f .env.production && cat .env.production", "log", shell("test -f .env.production && cat .env.production", "")},
		{"N09 source .env.production", "log", shell("source .env.production", "/bin/bash: line 1: .env.production: No such file or directory")},
		{"N10 Read tool on a missing file", "allowed", []gap0348Step{a348(g353ReadTool("PreToolUse", nil)),
			a348(g353ReadTool("PostToolUseFailure", map[string]interface{}{"error": "File does not exist."})),
			a348(g353ReadTool("PostToolUse", map[string]interface{}{"tool_response": map[string]interface{}{}}))}},
		{"N11 ls -la .env* (control)", "allowed", shell("ls -la .env*", "ls: cannot access '.env*': No such file or directory")},
		// GAP-0353: the in-actor Claude Code 2.1.323 pair.
		{"A01 in-actor failure then PostToolUse 'Error: Exit code 1'", "allowed", []gap0348Step{pre, a348(gap0352RealFailure()), a348(g353Post(c, "Error: Exit code 1\n"+g353Missing))}},
		{"A02 A01 with the failure on B", "allowed", []gap0348Step{pre, b348(gap0352RealFailure()), a348(g353Post(c, "Error: Exit code 1\n"+g353Missing))}},
		{"A03 A01 with the PostToolUse on B", "allowed", []gap0348Step{pre, a348(gap0352RealFailure()), b348(g353Post(c, "Error: Exit code 1\n"+g353Missing))}},
		{"A04 A01 with metadata and the cwd trailer", "allowed", []gap0348Step{pre, a348(gap0352RealFailure()), a348(g353Post(c, map[string]interface{}{"stdout": "", "stderr": g353Missing + "\nShell cwd was reset to /work", "interrupted": false, "isImage": false, "returnCodeInterpretation": "No such file or directory"}))}},
		{"A05 in-actor failure then a PostToolUse that printed", "refused", []gap0348Step{pre, a348(gap0352RealFailure()), a348(g353Post(c, "Error: Exit code 1\nAPI_KEY=canary-1"))}},
		// R1: a result whose Pre reached no leader is still marked.
		{"R01 no Pre, cleared result only", "log", []gap0348Step{clear}},
		{"R02 no Pre, cat < .env.production result only", "log", []gap0348Step{a348(g353Fail("cat < .env.production", "/bin/bash: line 1: .env.production: No such file or directory"))}},
	}
}

// The lead's rule 2 (STEER 7 and 8): review rk347b's matrix, lifted as a test. M rows must
// chain (no no-read result clears a read another result shows), B rows and the
// GAP-0353 rows must not; N01, N05 and N10 are the forms the proof now covers (rk347b
// P3-1), the other N rows the GAP-0337 residual (logged); L rows are not real shapes;
// R rows log the R1 mark of a result with no call.
func TestGAP0353Rule2Matrix(t *testing.T) {
	for _, row := range g353Rows() {
		t.Run(row.name, func(t *testing.T) {
			hooks, upload, v := gap0348Run(t, row.steps)
			var marks []int
			for i, h := range hooks {
				if slices.Contains(h.RuleIDs, substrateChainUnrecordedRule) {
					marks = append(marks, i)
				}
			}
			chained := slices.Contains(upload.RuleIDs, guardrail.ToolChainSecretReadThenEgress)
			refused := chained && upload.Action == guardrailActionBlock && v.Deny
			got := "allowed"
			switch {
			case refused:
				got = "refused"
			case v.Deny || upload.Action == guardrailActionBlock || v.Unrecorded != "":
				got = "blocked-other"
			}
			t.Logf("ROW %-75s want=%-7s got=%-13s marks=%v upload=%q chain=%v callout.deny=%v unrecorded=%v",
				row.name, row.want, got, marks, upload.Action, chained, v.Deny, v.Unrecorded != "")
			switch row.want {
			case "refused":
				if got != "refused" {
					t.Errorf("LAUNDER %s: got %s", row.name, got)
				}
			case "allowed":
				if got != "allowed" || len(marks) != 0 {
					t.Errorf("FALSEBLOCK %s: got %s marks %v", row.name, got, marks)
				}
			}
		})
	}
}
