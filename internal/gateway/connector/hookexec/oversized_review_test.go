// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"strings"
	"testing"
)

// The bounded review keeps every command-bearing key of every connector's
// payload, at any depth, before or after a long value and in arrays, and
// stays a valid request under the gateway's 1 MiB cap.
func TestOversizedReviewKeepsEveryCommandBearingKey(t *testing.T) {
	const secret = "cat ~/.ssh/id_rsa"
	long := strings.Repeat("d", 20<<10)
	pad := strings.Repeat("p", 2<<20)
	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		{"amp cmd", `{"hook_event_name":"tool.call","tool_name":"Bash","tool_input":{"cmd":"` + secret + `"},"padding":"` + pad + `"}`, []string{`"cmd":"` + secret + `"`}},
		{"codex exec_command cmd after a long value", `{"tool_name":"exec_command","tool_input":{"justification":"` + long + `","cmd":"` + secret + `","workdir":"/w"},"padding":"` + pad + `"}`, []string{`"cmd":"` + secret + `"`, `"workdir":"/w"`}},
		{"codex shell argv", `{"tool_name":"shell","tool_input":{"command":["bash","-lc","` + secret + `"]},"padding":"` + pad + `"}`, []string{`"command":["bash","-lc","` + secret + `"]`}},
		{"apply_patch input", `{"tool_name":"apply_patch","tool_input":{"input":"*** Begin Patch\n*** Add File: /home/a/.ssh/authorized_keys\n+k\n*** End Patch"},"padding":"` + pad + `"}`, []string{"authorized_keys"}},
		{"script, patch and target keys", `{"tool_input":{"script":"rm -rf ~/x","patch":"--- a/t","target":"/etc/sudoers","args":{"path":"/p"}},"padding":"` + pad + `"}`, []string{`"script":"rm -rf ~/x"`, `"patch":"--- a/t"`, `"target":"/etc/sudoers"`, `"path":"/p"`}},
		{"write content before file_path", `{"tool_name":"Write","tool_input":{"content":"` + long + `","file_path":"/home/a/.ssh/authorized_keys"},"padding":"` + pad + `"}`, []string{`"file_path":"/home/a/.ssh/authorized_keys"`}},
		{"key after an array", `{"workspace":["a","b"],"tool_input":{"command":"` + secret + `"},"padding":"` + pad + `"}`, []string{`"command":"` + secret + `"`}},
		{"nested object outside tool_input", `{"toolCall":{"name":"run_command","args":{"CommandLine":"` + secret + `"}},"padding":"` + pad + `"}`, []string{`"CommandLine":"` + secret + `"`}},
		{"copilot toolArgs cut by the cap", `{"toolName":"bash","toolArgs":"{\"command\":\"` + secret + `\",\"description\":\"` + pad + `\"}"}`, []string{`\"command\":\"` + secret + `\"`}},
		{"large command kept verbatim", `{"tool_input":{"command":"` + strings.Repeat("a", 300<<10) + ` ` + secret + `"},"padding":"` + pad + `"}`, []string{secret}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			review := oversizedReviewPayload([]byte(tc.body[:defaultMaxBody]), "PreToolUse")
			if len(review) == 0 || len(review) > oversizedReviewMaxBytes || !json.Valid(review) {
				t.Fatalf("review is not a valid bounded request: %d bytes", len(review))
			}
			for _, want := range tc.want {
				if !strings.Contains(string(review), want) {
					t.Fatalf("review lost %q: %.600s", want, review)
				}
			}
			for _, marker := range []string{`"bounded_prefix_review":true`, `"content_truncated":true`, `"hook_event_name":"PreToolUse"`} {
				if !strings.Contains(string(review), marker) {
					t.Fatalf("review lost marker %s: %.300s", marker, review)
				}
			}
		})
	}
}

// Context values stay bounded heads, so a large prefix of many fields is
// still a request the gateway accepts; a duplicated key is not reduced to
// one of its values (the gateway refuses it at full size).
func TestOversizedReviewBoundsContextAndRefusesDuplicateKeys(t *testing.T) {
	var many strings.Builder
	many.WriteString(`{"tool_input":{"command":"echo ok"},"tool_response":{"content":[`)
	for many.Len() < 2<<20 {
		many.WriteString(`{"type":"text","text":"` + strings.Repeat("r", 100) + `"},`)
	}
	review := oversizedReviewPayload([]byte(many.String()[:defaultMaxBody]), "PostToolUse")
	if len(review) == 0 || len(review) > oversizedReviewMaxBytes || !json.Valid(review) || !strings.Contains(string(review), `"command":"echo ok"`) {
		t.Fatalf("many-field review = %d bytes valid=%v", len(review), json.Valid(review))
	}
	dup := `{"tool_input":{"command":"cat ~/.ssh/id_rsa","command":"echo ok"},"padding":"` + strings.Repeat("p", 2<<20) + `"}`
	if review := oversizedReviewPayload([]byte(dup[:defaultMaxBody]), "PreToolUse"); review != nil {
		t.Fatalf("duplicate-key prefix was reduced to %.200s", review)
	}
}

// Loop round 2 (GAP-1022): a bounded review either carries every command
// and target value of the prefix whole, or is not sent at all (nil keeps the
// closed oversize answer). Budgets running out, a value the cap cut, a value
// nested too deep or a review over the gateway cap never yield a review the
// gateway could allow without the command.
func TestOversizedReviewNeverSendsACallWithoutItsWholeCommand(t *testing.T) {
	const secret = "cat ~/.ssh/id_rsa"
	notes := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(`"note` + strings.Repeat("n", i) + `":"` + strings.Repeat("z", 9000) + `",`)
		}
		return b.String()
	}
	// The reviewer's shape: 1,067,482 bytes, cmd at byte 811,442, after a
	// 528 KiB patch and 30 context fields that used up the old budgets.
	reviewer := `{"tool_name":"exec_command","tool_input":{"patch":"` + strings.Repeat("q", 528<<10) + `",` + notes(30) + `"cmd":"` + secret + `"},"padding":"`
	if at := strings.Index(reviewer, `"cmd"`); at < 800000 || at > 820000 {
		t.Fatalf("cmd at byte %d, want about 811,442", at)
	}
	reviewer += strings.Repeat("p", 1067482-len(reviewer)-2) + `"}`
	deep := `{"tool_input":{"command":` + strings.Repeat("[", oversizedReviewMaxDepth+2) + `"` + secret + `"` + strings.Repeat("]", oversizedReviewMaxDepth+2) + `},"padding":"` + strings.Repeat("p", 2<<20) + `"}`
	pad := strings.Repeat("p", 2<<20)
	for _, tc := range []struct {
		name, body string
		reviewed   bool // false: no review may be sent
		want       []string
	}{
		{"reviewer shape: cmd after the budgets ran out", reviewer, true, []string{`"cmd":"` + secret + `"`}},
		{"amp cmd after many context fields", `{"tool_name":"Bash","tool_input":{` + notes(40) + `"cmd":"` + secret + `"},"padding":"` + pad + `"}`, true, []string{`"cmd":"` + secret + `"`}},
		{"target after many context fields", `{"tool_name":"Write","tool_input":{` + notes(40) + `"file_path":"/home/a/.ssh/authorized_keys","content":"x"},"padding":"` + pad + `"}`, true, []string{`"file_path":"/home/a/.ssh/authorized_keys"`}},
		{"command values over the keep budget", `{"tool_input":{"patch":"` + strings.Repeat("q", 600<<10) + `","diff":"` + strings.Repeat("r", 350<<10) + `","cmd":"` + secret + `"},"padding":"` + pad + `"}`, false, nil},
		{"command cut by the cap", `{"tool_input":{"command":"echo ` + pad + `; ` + secret + `"}}`, false, nil},
		{"target cut by the cap", `{"tool_input":{"content":"x","file_path":"/home/a/` + pad + `"}}`, false, nil},
		{"command nested past the depth limit", deep, false, nil},
		{"copilot toolArgs command cut by the cap", `{"toolName":"bash","toolArgs":"{\"command\":\"echo ` + pad + `\"}"}`, false, nil},
		// Benign oversized calls keep their review (balanced defaults).
		{"lockfile write", `{"tool_name":"Write","tool_input":{"file_path":"/w/package-lock.json","content":"` + pad + `"}}`, true, []string{`"file_path":"/w/package-lock.json"`}},
		{"copilot create with a long file text", `{"toolName":"create","toolArgs":"{\"path\":\"/w/gen.go\",\"file_text\":\"` + pad + `\"}"}`, true, []string{`\"path\":\"/w/gen.go\"`}},
		{"large tool result", `{"hook_event_name":"PostToolUse","tool_name":"mcp__deepwiki__read_wiki_contents","tool_input":{"repoName":"a/b"},"tool_response":"` + pad + `"}`, true, []string{`"repoName":"a/b"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			review := oversizedReviewPayload([]byte(tc.body[:defaultMaxBody]), "PreToolUse")
			if !tc.reviewed {
				if review != nil {
					t.Fatalf("a review without the whole command or target was built (%d bytes)", len(review))
				}
				return
			}
			if len(review) == 0 || len(review) > oversizedReviewMaxBytes || !json.Valid(review) {
				t.Fatalf("review is not a valid bounded request: %d bytes", len(review))
			}
			for _, want := range tc.want {
				if !strings.Contains(string(review), want) {
					t.Fatalf("review lacks %q", want)
				}
			}
		})
	}
}
