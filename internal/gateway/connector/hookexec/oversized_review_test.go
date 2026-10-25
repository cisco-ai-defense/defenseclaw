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
func TestOversizedReviewMarksACallWithoutItsWholeCommand(t *testing.T) {
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
	// 160 Ki control bytes fit the keep budget whole, but their escaped form
	// (6 bytes each) keeps every pass over the gateway cap.
	escaped := `{"tool_input":{"cmd":"` + strings.Repeat(`\u0001`, 160<<10) + `"},"padding":"` + pad + `"}`
	for _, tc := range []struct {
		name, body string
		reviewed   bool // false: the review must be marked uninspected
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
		// The cap hides keys after it: a command after a long value of the
		// call's arguments was never read.
		{"bash command after a description cut by the cap", `{"tool_name":"Bash","tool_input":{"description":"` + pad + `","command":"` + secret + `"}}`, false, nil},
		{"write target after content cut by the cap", `{"tool_name":"Write","tool_input":{"content":"` + pad + `","file_path":"/home/a/.ssh/authorized_keys"}}`, false, nil},
		{"command after a nested context value cut by the cap", `{"tool_name":"Bash","tool_input":{"meta":{"notes":["` + pad + `"]},"command":"` + secret + `"}}`, false, nil},
		{"command array cut between its elements", `{"tool_input":{"command":["bash","-lc",` + strings.Repeat(`"x",`, 300000) + `"` + secret + `"]}}`, false, nil},
		{"copilot toolArgs with file text before its path", `{"toolName":"create","toolArgs":"{\"file_text\":\"` + pad + `\",\"path\":\"/home/a/.ssh/authorized_keys\"}"}`, false, nil},
		{"escaped command over the gateway cap", escaped, false, nil},
		// Benign oversized calls keep their review (balanced defaults).
		{"lockfile write", `{"tool_name":"Write","tool_input":{"file_path":"/w/package-lock.json","content":"` + pad + `"}}`, true, []string{`"file_path":"/w/package-lock.json"`}},
		{"copilot create with a long file text", `{"toolName":"create","toolArgs":"{\"path\":\"/w/gen.go\",\"file_text\":\"` + pad + `\"}"}`, true, []string{`\"path\":\"/w/gen.go\"`}},
		{"large tool result", `{"hook_event_name":"PostToolUse","tool_name":"mcp__deepwiki__read_wiki_contents","tool_input":{"repoName":"a/b"},"tool_response":"` + pad + `"}`, true, []string{`"repoName":"a/b"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := []byte(tc.body)
			if int64(len(prefix)) > defaultMaxBody {
				prefix = prefix[:defaultMaxBody]
			}
			review, uninspected := oversizedReview(prefix, "PreToolUse")
			if len(review) == 0 || len(review) > oversizedReviewMaxBytes || !json.Valid(review) {
				t.Fatalf("review is not a valid bounded request: %d bytes", len(review))
			}
			marked := strings.Contains(string(review), `"`+OversizeUninspectedField+`":true`)
			if marked != uninspected || marked == tc.reviewed {
				t.Fatalf("uninspected=%v marked=%v, want marked=%v: %.300s", uninspected, marked, !tc.reviewed, review)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(review), want) {
					t.Fatalf("review lacks %q", want)
				}
			}
		})
	}
}

// Loop round 1 review of 06bb83dd (GAP-1022): the call's arguments are
// written by the model in any order and may carry any key, so a value of
// them is never cut or dropped without the marker. A cut anywhere in the
// arguments marks the review, even after a command or target key was read,
// unless it lies in the file text of a file tool whose one target was read.
// Every argument value, whatever its key, is kept whole or marks the review.
func TestOversizedReviewMarksEveryHiddenArgument(t *testing.T) {
	const secret = "cat ~/.ssh/id_rsa"
	const target = "/home/a/.ssh/authorized_keys"
	pad := strings.Repeat("p", 2<<20)
	notes := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(`"note` + strings.Repeat("n", i) + `":"` + strings.Repeat("z", 9000) + `",`)
		}
		return b.String()
	}
	deep := `{"tool_name":"mcp__x__run","tool_input":{"a":` + strings.Repeat("[", oversizedReviewMaxDepth+2) + `"` + secret + `"` +
		strings.Repeat("]", oversizedReviewMaxDepth+2) + `},"padding":"` + pad + `"}`
	for _, tc := range []struct {
		name, body string
		reviewed   bool // false: the review must be marked uninspected
		want       []string
	}{
		// A cut after a command or target key still hides the keys after it.
		{"codex workdir then a cut justification hides cmd", `{"tool_name":"exec_command","tool_input":{"workdir":"/w","justification":"` + pad + `","cmd":"` + secret + `"}}`, false, nil},
		{"bash cwd then a cut description hides command", `{"tool_name":"Bash","tool_input":{"cwd":"/w","description":"` + pad + `","command":"` + secret + `"}}`, false, nil},
		{"bash command then a cut description hides workdir", `{"tool_name":"Bash","tool_input":{"command":"cat id_rsa","description":"` + pad + `","workdir":"/home/a/.ssh"}}`, false, nil},
		{"mcp source then cut content hides destination", `{"tool_name":"mcp__fs__move_file","tool_input":{"source":"/w/a","content":"` + pad + `","destination":"` + target + `"}}`, false, nil},
		{"copilot bash command then a cut description hides cwd", `{"toolName":"bash","toolArgs":"{\"command\":\"cat id_rsa\",\"description\":\"` + pad + `\",\"cwd\":\"/home/a/.ssh\"}"}`, false, nil},
		{"file tool with a second file text cut before its target", `{"tool_name":"Edit","tool_input":{"old_string":"` + pad + `","file_path":"` + target + `"}}`, false, nil},
		{"tool name after the arguments", `{"tool_input":{"file_path":"/w/a","content":"` + pad + `"},"tool_name":"Write"}`, false, nil},
		// Any argument key, not only the command and target names.
		{"argument nested past the depth limit under any key", deep, false, nil},
		{"unknown argument cut by the cap", `{"tool_name":"mcp__db__query","tool_input":{"sql":"` + pad + `"}}`, false, nil},
		{"unknown argument longer than a head is kept whole", `{"tool_name":"mcp__x__run","tool_input":{"location":"` + strings.Repeat("a", 20<<10) + target + `"},"padding":"` + pad + `"}`, true, []string{target + `"`}},
		{"unknown argument after context notes is kept", `{"tool_name":"mcp__x__run","tool_input":{` + notes(30) + `"location":"` + target + `"},"padding":"` + pad + `"}`, true, []string{`"location":"` + target + `"`}},
		{"copilot toolArgs unknown argument kept whole", `{"toolName":"mcp_x","toolArgs":"{\"location\":\"` + strings.Repeat("a", 20<<10) + target + `\"}","padding":"` + pad + `"}`, true, []string{target}},
		// A review over the per-user transports' 900 KiB body cap was refused
		// by defenseclaw-hook-post and failed closed, even in the default.
		{"command too long for the per-user transport", `{"tool_name":"Bash","tool_input":{"command":"` + strings.Repeat("a", 905000) + ` ` + secret + `"},"padding":"` + pad + `"}`, false, nil},
		// Benign oversized calls stay reviewed (balanced defaults, action too).
		{"edit with a long new string after its path", `{"tool_name":"Edit","tool_input":{"file_path":"/w/a.go","old_string":"x","new_string":"` + pad + `"}}`, true, []string{`"file_path":"/w/a.go"`}},
		{"multi edit with long edits after its path", `{"tool_name":"MultiEdit","tool_input":{"file_path":"/w/a.go","edits":[{"old_string":"x","new_string":"` + pad + `"}]}}`, true, []string{`"file_path":"/w/a.go"`}},
		{"notebook edit with a long source", `{"tool_name":"NotebookEdit","tool_input":{"notebook_path":"/w/n.ipynb","new_source":"` + pad + `"}}`, true, []string{`"notebook_path":"/w/n.ipynb"`}},
		{"long prompt", `{"hook_event_name":"UserPromptSubmit","prompt":"` + pad + `"}`, true, nil},
		{"long tool result after whole arguments", `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"cat package-lock.json","description":"` + strings.Repeat("d", 20<<10) + `"},"tool_response":{"stdout":"` + pad + `"}}`, true, []string{`"command":"cat package-lock.json"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := []byte(tc.body)
			if int64(len(prefix)) > defaultMaxBody {
				prefix = prefix[:defaultMaxBody]
			}
			review, uninspected := oversizedReview(prefix, "PreToolUse")
			if len(review) == 0 || len(review) > 900<<10 || !json.Valid(review) {
				t.Fatalf("review is not a valid bounded request: %d bytes", len(review))
			}
			marked := strings.Contains(string(review), `"`+OversizeUninspectedField+`":true`)
			if marked != uninspected || marked == tc.reviewed {
				t.Fatalf("uninspected=%v marked=%v, want marked=%v: %.300s", uninspected, marked, !tc.reviewed, review)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(review), want) {
					t.Fatalf("review lacks %q", want)
				}
			}
		})
	}
}
