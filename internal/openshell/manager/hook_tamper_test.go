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

package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestToolCallHooksClassify(t *testing.T) {
	for _, tt := range []struct {
		connector, event, status string
		pre                      bool
		result                   toolResult
	}{
		// A decision that names no connector reads Claude Code's events.
		{"", "PreToolUse", "", true, toolResultNone},
		{"", "PostToolUse", "", false, toolResultRan},
		{"", "PostToolUseFailure", "", false, toolResultFailed},
		{"", "PermissionDenied", "", false, toolResultRefused},
		{"claudecode", "PreToolUse", "", true, toolResultNone},
		{"claudecode", "PostToolUse", "", false, toolResultRan},
		{"claudecode", "PostToolUseFailure", "", false, toolResultFailed},
		{"claudecode", "PermissionDenied", "", false, toolResultRefused},
		{"codex", "PreToolUse", "", true, toolResultNone},
		{"codex", "PostToolUse", "", false, toolResultRan},
		{"cursor", "preToolUse", "", true, toolResultNone},
		{"cursor", "postToolUse", "", false, toolResultRan},
		{"cursor", "postToolUseFailure", "", false, toolResultFailed},
		{"opencode", "tool.execute.before", "", true, toolResultNone},
		{"opencode", "tool.execute.after", "", false, toolResultRan},
		{"amp", "tool.call", "", true, toolResultNone},
		{"amp", "tool.result", "done", false, toolResultRan},
		{"amp", "tool.result", " done ", false, toolResultRan},
		{"amp", "tool.result", "error", false, toolResultFailed},
		{"amp", "tool.result", "cancelled", false, toolResultFailed},
		{"amp", "tool.result", "", false, toolResultFailed},
		{"amp", "tool.result", "Done", false, toolResultFailed},
		{"kiro", "preToolUse", "", true, toolResultNone},
		{"kiro", "postToolUse", "", false, toolResultRan},
		{"copilot", "preToolUse", "", true, toolResultNone},
		{"copilot", "postToolUse", "", false, toolResultRan},
		{"copilot", "postToolUseFailure", "", false, toolResultFailed},
		{"devin", "PreToolUse", "", true, toolResultNone},
		{"devin", "PostToolUse", "", false, toolResultRan},
		// Exact vendor spellings of each harness only.
		{"", "preToolUse", "", false, toolResultNone},
		{"claudecode", "post_tool_use", "", false, toolResultNone},
		{"claudecode", "PermissionRequest", "", false, toolResultNone},
		{"claudecode", "PostToolBatch", "", false, toolResultNone},
		{"claudecode", "SessionStart", "", false, toolResultNone},
		{"codex", "PermissionDenied", "", false, toolResultNone},
		{"cursor", "PreToolUse", "", false, toolResultNone},
		{"cursor", "beforeShellExecution", "", false, toolResultNone},
		{"cursor", "afterShellExecution", "", false, toolResultNone},
		{"kiro", "PreToolUse", "", false, toolResultNone},
		{"kiro", "userPromptSubmit", "", false, toolResultNone},
		{"kiro", "stop", "", false, toolResultNone},
		{"copilot", "permissionRequest", "", false, toolResultNone},
		{"opencode", "tool.execute.after", "done", false, toolResultRan},
		{"amp", "agent.end", "done", false, toolResultNone},
		{"kiro", "", "", false, toolResultNone},
		{"hermes", "pre_tool_call", "", true, toolResultNone},
		{"hermes", "post_tool_call", "", false, toolResultRan},
		{"hermes", "PreToolUse", "", false, toolResultNone},
		{"openhands", "PreToolUse", "", true, toolResultNone},
		{"antigravity", "PostToolUse", "", false, toolResultRan},
		{"omnigent", "PreToolUse", "", true, toolResultNone},
		// A connector with no reviewed tool-call hooks names nothing.
		{"future", "PreToolUse", "", false, toolResultNone},
	} {
		pre, result := toolCallHooksFor(tt.connector).classify(tt.event, tt.status)
		if pre != tt.pre || result != tt.result {
			t.Errorf("%s: classify(%q, %q) = %v, %v; want %v, %v", tt.connector, tt.event, tt.status, pre, result, tt.pre, tt.result)
		}
	}
}

// Every sandboxed harness is listed, and each pairs by the identity its
// hooks carry: a per-call ID (Claude Code, Codex, Cursor, OpenCode, Amp),
// the call's content (Kiro CLI, measured to send none), or nothing (Copilot
// CLI, Devin CLI, Hermes, OpenHands, Antigravity and OmniGent, whose
// post-tool events on a denied call are not measured).
func TestToolCallHooksKeying(t *testing.T) {
	want := map[string]toolCallKeying{
		"claudecode": keyByID, "codex": keyByID, "cursor": keyByID, "opencode": keyByID, "amp": keyByID,
		"kiro": keyByContent, "copilot": keyNone, "devin": keyNone,
		"hermes": keyNone, "openhands": keyNone, "antigravity": keyNone, "omnigent": keyNone,
	}
	if len(toolCallHooksByConnector) != len(want) {
		t.Fatalf("toolCallHooksByConnector lists %d connectors, want %d", len(toolCallHooksByConnector), len(want))
	}
	for name, keying := range want {
		hooks, ok := toolCallHooksByConnector[name]
		if !ok || hooks.keying != keying || hooks.pre == "" || (hooks.ran == "" && hooks.statusResult == "") {
			t.Errorf("%s: hooks %+v, want keying %d", name, hooks, keying)
		}
	}
}

func TestToolCallRefs(t *testing.T) {
	if ref := idRef("  "); ref.key != "" {
		t.Fatalf("blank ID names %+v", ref)
	}
	if ref := idRef(" toolu_1 "); ref.key != "toolu_1" || ref.byContent {
		t.Fatalf("idRef = %+v", ref)
	}
	long := idRef(strings.Repeat("x", 4096))
	if !strings.HasPrefix(long.key, "sha256:") || len(long.key) > 80 {
		t.Fatalf("oversized ID = %q", long.key)
	}

	a := contentRef("sess-1", "shell", json.RawMessage(`{"command":"echo a","cwd":"/work"}`))
	if a.key == "" || !a.byContent || !strings.HasPrefix(a.key, "call:") {
		t.Fatalf("contentRef = %+v", a)
	}
	// The same call spelled with other whitespace and key order.
	if b := contentRef(" sess-1 ", " shell ", json.RawMessage("{ \"cwd\": \"/work\",\n \"command\": \"echo a\" }")); b != a {
		t.Fatalf("equivalent input keyed %q, want %q", b.key, a.key)
	}
	for name, other := range map[string]toolCallRef{
		"input":   contentRef("sess-1", "shell", json.RawMessage(`{"command":"echo b","cwd":"/work"}`)),
		"tool":    contentRef("sess-1", "fs_read", json.RawMessage(`{"command":"echo a","cwd":"/work"}`)),
		"session": contentRef("sess-2", "shell", json.RawMessage(`{"command":"echo a","cwd":"/work"}`)),
		// The fields are separated, so moving a byte across them changes
		// the key.
		"boundary": contentRef("sess-1s", "hell", json.RawMessage(`{"command":"echo a","cwd":"/work"}`)),
		// Numbers are kept verbatim, not rounded through float64.
		"number": contentRef("sess-1", "shell", json.RawMessage(`{"n":12345678901234567891}`)),
	} {
		if other.key == a.key {
			t.Errorf("%s: a different call shares the key", name)
		}
	}
	if n1, n2 := contentRef("s", "t", json.RawMessage(`{"n":12345678901234567891}`)), contentRef("s", "t", json.RawMessage(`{"n":12345678901234567892}`)); n1 == n2 {
		t.Error("large numbers that differ share a key")
	}
	for _, missing := range []toolCallRef{
		contentRef("sess-1", "", json.RawMessage(`{"command":"echo a"}`)),
		contentRef("sess-1", "shell", nil),
		contentRef("sess-1", "shell", json.RawMessage("  ")),
	} {
		if missing.key != "" {
			t.Errorf("a call without a tool or input named %+v", missing)
		}
	}
	// Input that is not JSON is keyed verbatim.
	if raw := contentRef("s", "t", json.RawMessage("not json")); raw.key == "" {
		t.Error("non-JSON input named no call")
	}
}

func TestHookTamperTrackerVerdicts(t *testing.T) {
	type step struct {
		pre    bool
		denied bool
		result toolResult
		want   tamperKind
	}
	for _, tt := range []struct {
		name     string
		complete bool
		steps    []step
	}{
		{"allowed then ran", true, []step{{pre: true}, {result: toolResultRan}}},
		{"denied then ran", true, []step{{pre: true, denied: true}, {result: toolResultRan, want: tamperDenied}}},
		{"never seen then ran", true, []step{{result: toolResultRan, want: tamperUnseen}}},
		{"repeated result is reported once", true, []step{
			{result: toolResultRan, want: tamperUnseen}, {result: toolResultRan},
		}},
		{"denied result reported once", true, []step{
			{pre: true, denied: true}, {result: toolResultRan, want: tamperDenied}, {result: toolResultRan},
		}},
		{"allowed result repeated", true, []step{{pre: true}, {result: toolResultRan}, {result: toolResultRan}}},
		// Claude can report a failure before PreToolUse ran (invalid input)
		// and reports its own refusals; neither proves the tool ran.
		{"failure without pre", true, []step{{result: toolResultFailed}}},
		{"refusal without pre", true, []step{{result: toolResultRefused}}},
		{"denied then failure", true, []step{{pre: true, denied: true}, {result: toolResultFailed}}},
		{"denied, failure, then ran", true, []step{
			{pre: true, denied: true}, {result: toolResultFailed}, {result: toolResultRan, want: tamperDenied},
		}},
		{"a later allowed pre cannot clear a denial", true, []step{
			{pre: true, denied: true}, {pre: true}, {result: toolResultRan, want: tamperDenied},
		}},
		// A ledger this process did not begin (a sandbox adopted after a
		// restart) cannot prove a call was never seen, but still knows
		// its own denials.
		{"partial: never seen then ran", false, []step{{result: toolResultRan}}},
		{"partial: denied then ran", false, []step{{pre: true, denied: true}, {result: toolResultRan, want: tamperDenied}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tr := newHookTamperTracker()
			if tt.complete {
				tr.Begin("b1")
			}
			for i, s := range tt.steps {
				if s.pre {
					tr.ObservePre("b1", idRef("toolu_1"), s.denied)
					continue
				}
				if got := tr.ObserveResult("b1", idRef("toolu_1"), s.result); got != s.want {
					t.Fatalf("step %d: verdict %v, want %v", i, got, s.want)
				}
			}
		})
	}
}

// A content key is shared by identical calls (Kiro CLI sends no per-call
// ID), so the ledger counts open calls, and a later call's own verdict
// decides rather than an earlier identical one's.
func TestHookTamperTrackerContentKeys(t *testing.T) {
	type step struct {
		pre    bool
		denied bool
		result toolResult
		want   tamperKind
	}
	for _, tt := range []struct {
		name     string
		complete bool
		steps    []step
	}{
		{"allowed then ran", true, []step{{pre: true}, {result: toolResultRan}}},
		{"denied then ran", true, []step{{pre: true, denied: true}, {result: toolResultRan, want: tamperDenied}}},
		{"never seen then ran", true, []step{{result: toolResultRan, want: tamperUnseen}}},
		{"two identical calls, both paired", true, []step{
			{pre: true}, {pre: true}, {result: toolResultRan}, {result: toolResultRan},
		}},
		// The pre-tool hook of the second identical call was killed, but
		// DefenseClaw allowed exactly this call: no verdict was bypassed.
		{"repeat of an allowed call", true, []step{
			{pre: true}, {result: toolResultRan}, {result: toolResultRan},
		}},
		// The agent retried a denied call and DefenseClaw allowed it the
		// second time (an approval, a lifted block): not tamper.
		{"denied, then allowed, then ran", true, []step{
			{pre: true, denied: true}, {pre: true}, {result: toolResultRan},
		}},
		{"allowed, ran, denied, then ran", true, []step{
			{pre: true}, {result: toolResultRan}, {pre: true, denied: true}, {result: toolResultRan, want: tamperDenied},
		}},
		{"denied twice then ran", true, []step{
			{pre: true, denied: true}, {pre: true, denied: true}, {result: toolResultRan, want: tamperDenied}, {result: toolResultRan},
		}},
		// A denial of an identical call while one is open leaves the open
		// call to pair with the next result.
		{"denied while an identical call is open", true, []step{
			{pre: true}, {pre: true, denied: true}, {result: toolResultRan}, {result: toolResultRan},
		}},
		{"failure closes one open call", true, []step{
			{pre: true}, {pre: true}, {result: toolResultFailed}, {result: toolResultRan}, {result: toolResultRan},
		}},
		{"partial: never seen then ran", false, []step{{result: toolResultRan}}},
		{"partial: denied then ran", false, []step{{pre: true, denied: true}, {result: toolResultRan, want: tamperDenied}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tr := newHookTamperTracker()
			if tt.complete {
				tr.Begin("b1")
			}
			call := contentRef("sess-1", "shell", json.RawMessage(`{"command":"echo dctamper"}`))
			for i, s := range tt.steps {
				if s.pre {
					tr.ObservePre("b1", call, s.denied)
					continue
				}
				if got := tr.ObserveResult("b1", call, s.result); got != s.want {
					t.Fatalf("step %d: verdict %v, want %v", i, got, s.want)
				}
			}
		})
	}
}

// Open content calls stay bounded, and an evicted one is remembered as
// seen.
func TestHookTamperTrackerContentKeysBounded(t *testing.T) {
	tr := newHookTamperTracker()
	tr.Begin("b1")
	task := contentRef("s", "shell", json.RawMessage(`{"command":"sleep 600"}`))
	tr.ObservePre("b1", task, false)
	tr.ObservePre("b1", task, false)
	echo := func(i int) toolCallRef {
		return contentRef("s", "shell", json.RawMessage(fmt.Sprintf(`{"command":"echo %d"}`, i)))
	}
	for i := 0; i < maxOpenToolCalls; i++ {
		tr.ObservePre("b1", echo(i), false)
	}
	if got := tr.ObserveResult("b1", task, toolResultRan); got != tamperNone {
		t.Fatalf("evicted open call = %v", got)
	}
	for i := 0; i < 3*maxOpenToolCalls; i++ {
		tr.ObservePre("b1", echo(maxOpenToolCalls+i), false)
		tr.ObservePre("b1", echo(maxOpenToolCalls+i), false)
	}
	tr.mu.Lock()
	open, past := tr.bindings["b1"].open.Len(), tr.bindings["b1"].past.Len()
	tr.mu.Unlock()
	if open > maxOpenToolCalls || past > maxPastToolCalls {
		t.Fatalf("open %d past %d, bounds %d and %d", open, past, maxOpenToolCalls, maxPastToolCalls)
	}
}

func TestHookTamperTrackerIgnoresUncorrelatable(t *testing.T) {
	tr := newHookTamperTracker()
	tr.Begin("b1")
	tr.ObservePre("b1", idRef(""), true)
	if got := tr.ObserveResult("b1", idRef(""), toolResultRan); got != tamperNone {
		t.Fatalf("a result without a tool-use ID = %v", got)
	}
	if got := tr.ObserveResult("", idRef("toolu_1"), toolResultRan); got != tamperNone {
		t.Fatalf("a result without a binding = %v", got)
	}
	if n, _ := tr.tracked("b1"); n != 0 {
		t.Fatalf("tracked %d uncorrelatable calls", n)
	}
	// Bindings do not share calls.
	tr.Begin("b2")
	tr.ObservePre("b1", idRef("toolu_1"), false)
	if got := tr.ObserveResult("b2", idRef("toolu_1"), toolResultRan); got != tamperUnseen {
		t.Fatalf("another binding's call = %v", got)
	}
}

func TestHookTamperTrackerBoundedMemory(t *testing.T) {
	tr := newHookTamperTracker()
	tr.Begin("b1")
	// An oversized ID is kept as its digest and still pairs.
	long := strings.Repeat("x", 4096)
	tr.ObservePre("b1", idRef(long), false)
	if got := tr.ObserveResult("b1", idRef(long), toolResultRan); got != tamperNone {
		t.Fatalf("oversized ID did not pair: %v", got)
	}
	for i := 0; i < 5*(maxOpenToolCalls+maxPastToolCalls); i++ {
		id := fmt.Sprintf("toolu_%d", i)
		tr.ObservePre("b1", idRef(id), i%3 == 0)
		if i%2 == 0 {
			tr.ObserveResult("b1", idRef(id), toolResultRan)
		}
	}
	for i := 0; i < 5*maxPastToolCalls; i++ {
		tr.ObserveResult("b1", idRef(fmt.Sprintf("unseen_%d", i)), toolResultRan)
	}
	n, _ := tr.tracked("b1")
	if n > maxOpenToolCalls+maxPastToolCalls {
		t.Fatalf("tracked %d calls, bound is %d", n, maxOpenToolCalls+maxPastToolCalls)
	}
	tr.mu.Lock()
	l := tr.bindings["b1"]
	open, past := l.open.Len(), l.past.Len()
	tr.mu.Unlock()
	if open > maxOpenToolCalls || past > maxPastToolCalls || open+past != n {
		t.Fatalf("open %d past %d tracked %d", open, past, n)
	}
}

// A long-running call pushed out of the open set by many newer calls is
// remembered as seen: its result is not tamper.
func TestHookTamperTrackerEvictedOpenCallIsNotTamper(t *testing.T) {
	tr := newHookTamperTracker()
	tr.Begin("b1")
	tr.ObservePre("b1", idRef("toolu_task"), false)
	for i := 0; i < maxOpenToolCalls; i++ {
		tr.ObservePre("b1", idRef(fmt.Sprintf("toolu_%d", i)), false)
	}
	if got := tr.ObserveResult("b1", idRef("toolu_task"), toolResultRan); got != tamperNone {
		t.Fatalf("evicted open call = %v", got)
	}
}

func TestHookTamperTrackerForgetBeginRetain(t *testing.T) {
	tr := newHookTamperTracker()
	tr.Begin("b1")
	tr.ObservePre("b1", idRef("toolu_1"), true)
	tr.Forget("b1")
	if _, ok := tr.tracked("b1"); ok {
		t.Fatal("ledger survived Forget")
	}
	// Begin starts over: an earlier session's denial is gone.
	tr.Begin("b2")
	tr.ObservePre("b2", idRef("toolu_1"), true)
	tr.Begin("b2")
	if got := tr.ObserveResult("b2", idRef("toolu_1"), toolResultRan); got != tamperUnseen {
		t.Fatalf("after Begin = %v, want unseen", got)
	}
	tr.ObservePre("b3", idRef("toolu_1"), false)
	tr.Retain(func(id string) bool { return id == "b3" })
	if _, ok := tr.tracked("b2"); ok {
		t.Fatal("Retain kept a dead binding")
	}
	if _, ok := tr.tracked("b3"); !ok {
		t.Fatal("Retain dropped a live binding")
	}
}

func hookTamperFindings(e *harnessEnv) []audit.SandboxFindingEvent {
	e.tel.mu.Lock()
	defer e.tel.mu.Unlock()
	var out []audit.SandboxFindingEvent
	for _, f := range e.tel.findings {
		if f.Kind == audit.SandboxFindingHookTamper {
			out = append(out, f)
		}
	}
	return out
}

func tamperFeed(e *harnessEnv, name string) []sandboxapi.ActivityEvent {
	var out []sandboxapi.ActivityEvent
	for _, ev := range e.m.ActivitySince(0, name) {
		if ev.Kind == sandboxapi.ActivityFinding && ev.Reason == string(audit.SandboxFindingHookTamper) {
			out = append(out, ev)
		}
	}
	return out
}

func TestHookTamperAlert(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "tamperalert"})
	if sb.Pack != packs.DefaultPack {
		t.Fatalf("pack = %q", sb.Pack)
	}
	binding, _ := e.store.Lookup(sb.Name)
	d := func(event, id, action string) HookDecision {
		return HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: event, Tool: "Bash", ToolUseID: id, Action: action}
	}
	// A paired call, a harness-reported failure and a refusal: no tamper.
	e.m.ObserveHookDecision(d("PreToolUse", "toolu_ok", "allow"))
	e.m.ObserveHookDecision(d("PostToolUse", "toolu_ok", "allow"))
	e.m.ObserveHookDecision(d("PostToolUseFailure", "toolu_fail", "allow"))
	e.m.ObserveHookDecision(d("PermissionDenied", "toolu_refused", "allow"))
	if f := hookTamperFindings(e); len(f) != 0 {
		t.Fatalf("findings for paired calls: %+v", f)
	}

	// The PreToolUse hook was killed: only the PostToolUse arrives.
	e.m.ObserveHookDecision(d("PostToolUse", "toolu_killed", "allow"))
	// A denied call that ran anyway.
	e.m.ObserveHookDecision(d("PreToolUse", "toolu_denied", "block"))
	e.m.ObserveHookDecision(d("PostToolUse", "toolu_denied", "allow"))
	// A replayed result is not reported again.
	e.m.ObserveHookDecision(d("PostToolUse", "toolu_killed", "allow"))

	findings := hookTamperFindings(e)
	if len(findings) != 2 {
		t.Fatalf("hook tamper findings = %+v", findings)
	}
	for _, f := range findings {
		if f.Severity != "HIGH" || f.Sandbox.Name != sb.Name || f.TargetRef != sb.Name ||
			!strings.Contains(f.Remediation, "hooks.on_tamper: alert") || !strings.Contains(f.Evidence, "tool=Bash") {
			t.Fatalf("finding = %+v", f)
		}
	}
	if !strings.Contains(findings[0].Title, "without a DefenseClaw verdict") || !strings.Contains(findings[0].Evidence, "tool_use_id=toolu_killed") {
		t.Fatalf("unseen finding = %+v", findings[0])
	}
	if !strings.Contains(findings[1].Title, "denied ran anyway") {
		t.Fatalf("denied finding = %+v", findings[1])
	}
	feed := tamperFeed(e, sb.Name)
	if len(feed) != 2 || feed[0].Severity != "HIGH" || feed[0].Tool != "Bash" || !strings.Contains(feed[0].Message, "keeps running") {
		t.Fatalf("feed = %+v", feed)
	}
	got, _ := e.m.Get(context.Background(), sb.Name)
	if got.Phase != "ready" || got.Hooks.Tampered != 2 || got.Hooks.LastTamperAt.IsZero() {
		t.Fatalf("alert pack: phase %s hooks %+v", got.Phase, got.Hooks)
	}
	// The denied PreToolUse still counts as a blocked tool call.
	if got.Hooks.ToolBlocked != 1 || got.Hooks.ToolCalls != 2 {
		t.Fatalf("hooks = %+v", got.Hooks)
	}
}

// Each sandboxed harness's own tool-call events pair: a killed pre-tool
// hook, and a denied call that ran anyway, are reported for every harness
// whose hooks name a call, and never for one whose hooks do not.
func TestHookTamperPerHarness(t *testing.T) {
	type call struct {
		id, session string
		input       json.RawMessage
	}
	for _, tc := range []struct {
		connector, pre, post, status string
		// byContent: the harness sends no per-call ID (Kiro CLI).
		byContent bool
		// paired is false for harnesses whose calls are not paired.
		paired bool
	}{
		{connector: "claudecode", pre: "PreToolUse", post: "PostToolUse", paired: true},
		{connector: "codex", pre: "PreToolUse", post: "PostToolUse", paired: true},
		{connector: "cursor", pre: "preToolUse", post: "postToolUse", paired: true},
		{connector: "opencode", pre: "tool.execute.before", post: "tool.execute.after", paired: true},
		{connector: "amp", pre: "tool.call", post: "tool.result", status: "done", paired: true},
		{connector: "kiro", pre: "preToolUse", post: "postToolUse", byContent: true, paired: true},
		{connector: "copilot", pre: "preToolUse", post: "postToolUse"},
		{connector: "devin", pre: "PreToolUse", post: "PostToolUse"},
		{connector: "hermes", pre: "pre_tool_call", post: "post_tool_call"},
		{connector: "openhands", pre: "PreToolUse", post: "PostToolUse"},
		{connector: "antigravity", pre: "PreToolUse", post: "PostToolUse"},
		{connector: "omnigent", pre: "PreToolUse", post: "PostToolUse"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			e := newEnv(t, nil)
			sb := e.create(sandboxapi.CreateRequest{Name: "tamper" + tc.connector})
			binding, _ := e.store.Lookup(sb.Name)
			d := func(event, action string, c call) HookDecision {
				out := HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Connector: tc.connector,
					Event: event, Tool: "shell", SessionID: c.session, ToolInput: c.input, Action: action}
				if !tc.byContent {
					out.ToolUseID = c.id
				}
				if event == tc.post {
					out.ResultStatus = tc.status
				}
				return out
			}
			calls := map[string]call{}
			for _, name := range []string{"ok", "killed", "denied", "refused"} {
				calls[name] = call{id: "call_" + name, session: "sess-1", input: json.RawMessage(`{"command":"echo dctamper-` + name + `"}`)}
			}
			// A paired call: no tamper.
			e.m.ObserveHookDecision(d(tc.pre, "allow", calls["ok"]))
			e.m.ObserveHookDecision(d(tc.post, "allow", calls["ok"]))
			if f := hookTamperFindings(e); len(f) != 0 {
				t.Fatalf("a paired call raised %+v", f)
			}
			// The pre-tool hook was killed: only the post-tool event arrives.
			e.m.ObserveHookDecision(d(tc.post, "allow", calls["killed"]))
			// A denied call that ran anyway.
			e.m.ObserveHookDecision(d(tc.pre, "block", calls["denied"]))
			e.m.ObserveHookDecision(d(tc.post, "allow", calls["denied"]))

			findings := hookTamperFindings(e)
			if !tc.paired {
				if len(findings) != 0 {
					t.Fatalf("%s calls are not paired, but raised %+v", tc.connector, findings)
				}
				return
			}
			if len(findings) != 2 {
				t.Fatalf("hook tamper findings = %+v", findings)
			}
			if !strings.Contains(findings[0].Title, "without a DefenseClaw verdict") ||
				!strings.Contains(findings[0].Description, "its "+tc.pre+" hook never reached DefenseClaw") ||
				!strings.Contains(findings[0].Evidence, "event="+tc.post) {
				t.Fatalf("unseen finding = %+v", findings[0])
			}
			if !strings.Contains(findings[1].Title, "denied ran anyway") || !strings.Contains(findings[1].Description, "denied its "+tc.pre) {
				t.Fatalf("denied finding = %+v", findings[1])
			}
			if tc.byContent == strings.Contains(findings[0].Evidence, "tool_use_id=") {
				t.Fatalf("evidence %q: a tool_use_id belongs to ID-keyed calls only", findings[0].Evidence)
			}
			if tc.connector == "amp" {
				// A tool.result that is not done closes the call without
				// proving it ran, even for a call DefenseClaw denied.
				e.m.ObserveHookDecision(d(tc.pre, "block", calls["refused"]))
				refused := d(tc.post, "allow", calls["refused"])
				refused.ResultStatus = "cancelled"
				e.m.ObserveHookDecision(refused)
				if f := hookTamperFindings(e); len(f) != 2 {
					t.Fatalf("a cancelled tool.result raised %+v", f[2:])
				}
			}
		})
	}
}

func TestHookTamperStop(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "tamperstop", Pack: "balanced"})
	binding, _ := e.store.Lookup(sb.Name)
	d := func(event, id string) HookDecision {
		return HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: event, Tool: "Bash", ToolUseID: id, Action: "allow"}
	}
	e.m.ObserveHookDecision(d("PostToolUse", "toolu_1"))
	e.m.ObserveHookDecision(d("PostToolUse", "toolu_2"))
	e.m.tamperStops.Wait()
	if got, _ := e.client.GetSandbox(context.Background(), sb.Name); got == nil || got.Status.Phase != openshell.PhaseStopped {
		t.Fatalf("the tampered sandbox did not stop: %+v", got)
	}
	findings := hookTamperFindings(e)
	if len(findings) != 2 || !strings.Contains(findings[0].Remediation, "hooks.on_tamper: stop") {
		t.Fatalf("findings = %+v", findings)
	}
	feed := tamperFeed(e, sb.Name)
	if len(feed) != 2 || !strings.Contains(feed[0].Message, "stopping the sandbox") ||
		!strings.Contains(feed[1].Message, "already stopping") {
		t.Fatalf("feed = %+v", feed)
	}
	var stops int
	e.tel.mu.Lock()
	for _, ev := range e.tel.lifecycle {
		if ev.Sandbox.Name == sb.Name && ev.Trigger == audit.SandboxTriggerStop && ev.Sandbox.Phase == audit.SandboxPhaseStopping {
			stops++
		}
	}
	e.tel.mu.Unlock()
	if stops != 1 {
		t.Fatalf("stops = %d, want one", stops)
	}

	// A new session starts with a clean ledger and may be stopped again.
	if _, err := e.m.Start(context.Background(), sb.Name, sandboxapi.StartRequest{}); err != nil {
		t.Fatal(err)
	}
	binding, _ = e.store.Lookup(sb.Name)
	e.m.ObserveHookDecision(HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PreToolUse", Tool: "Bash", ToolUseID: "toolu_3", Action: "allow"})
	e.m.ObserveHookDecision(HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PostToolUse", Tool: "Bash", ToolUseID: "toolu_3", Action: "allow"})
	if got, _ := e.m.Get(context.Background(), sb.Name); got.Phase != "ready" {
		t.Fatalf("a paired call stopped the sandbox: %s", got.Phase)
	}
	e.m.ObserveHookDecision(HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PostToolUse", Tool: "Bash", ToolUseID: "toolu_4", Action: "allow"})
	e.m.tamperStops.Wait()
	if got, _ := e.client.GetSandbox(context.Background(), sb.Name); got == nil || got.Status.Phase != openshell.PhaseStopped {
		t.Fatalf("the second session did not stop: %+v", got)
	}
}

func TestHookTamperIgnoresStaleBindingAndForgets(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "tamperstale"})
	binding, _ := e.store.Lookup(sb.Name)
	// A decision for another binding of the name neither alarms nor leaves
	// a ledger behind.
	e.m.ObserveHookDecision(HookDecision{BindingID: "sb_other", SandboxName: sb.Name, Event: "PostToolUse", ToolUseID: "toolu_1"})
	if f := hookTamperFindings(e); len(f) != 0 {
		t.Fatalf("stale binding raised %+v", f)
	}
	if _, ok := e.m.toolCalls.tracked("sb_other"); ok {
		t.Fatal("stale binding got a ledger")
	}
	e.m.ObserveHookDecision(HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PreToolUse", ToolUseID: "toolu_1", Action: "allow"})
	if _, ok := e.m.toolCalls.tracked(binding.ID); !ok {
		t.Fatal("no ledger for the live binding")
	}
	if _, err := e.m.Delete(context.Background(), sb.Name, sandboxapi.DeleteRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.m.toolCalls.tracked(binding.ID); ok {
		t.Fatal("the revoked binding's ledger survived the delete")
	}
	// A decision that raced the revoke is collected by the next prune.
	e.m.toolCalls.ObservePre(binding.ID, idRef("toolu_2"), false)
	e.m.pruneToolCalls()
	if _, ok := e.m.toolCalls.tracked(binding.ID); ok {
		t.Fatal("prune kept a dead binding's ledger")
	}
}

// After a daemon restart the running sandbox's ledger is partial: a result
// for a call from before the restart is not tamper, a denial seen after it
// still is.
func TestHookTamperAfterRestart(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "tamperrestart", Pack: "balanced"})
	binding, _ := e.store.Lookup(sb.Name)
	e.m.ObserveHookDecision(HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PreToolUse", ToolUseID: "toolu_before", Action: "allow"})

	e.m = e.newManager()
	e.run()
	eventually(t, "startup reconcile", func() bool {
		st, _ := e.m.Status(context.Background())
		return !st.LastReconcile.IsZero()
	})
	e.m.ObserveHookDecision(HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PostToolUse", Tool: "Bash", ToolUseID: "toolu_before", Action: "allow"})
	if f := hookTamperFindings(e); len(f) != 0 {
		t.Fatalf("a call from before the restart raised %+v", f)
	}
	e.m.ObserveHookDecision(HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PreToolUse", Tool: "Bash", ToolUseID: "toolu_after", Action: "block"})
	e.m.ObserveHookDecision(HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PostToolUse", Tool: "Bash", ToolUseID: "toolu_after", Action: "allow"})
	if f := hookTamperFindings(e); len(f) != 1 || !strings.Contains(f[0].Remediation, "hooks.on_tamper: stop") {
		t.Fatalf("denied call after the restart: %+v", f)
	}
	e.m.tamperStops.Wait()
	if got, _ := e.client.GetSandbox(context.Background(), sb.Name); got == nil || got.Status.Phase != openshell.PhaseStopped {
		t.Fatalf("the adopted sandbox did not stop: %+v", got)
	}
}

func TestHookLabel(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Bash", "Bash"},
		{" mcp__github__create_issue ", "mcp__github__create_issue"},
		{"a b\tc\n\x1b[31m\"\\", "abc[31m"},
		{strings.Repeat("y", 100), strings.Repeat("y", 64)},
	} {
		if got := hookLabel(tc.in, 64); got != tc.want {
			t.Errorf("hookLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDisplayReason(t *testing.T) {
	plain := "Blocked by DefenseClaw rule CMD-1: Title. Do this instead."
	for _, tc := range []struct{ in, want string }{
		{plain, plain},
		{"  plain  ", "plain"},
		{"<redacted len=12 sha=0123abcd>", ""},
		{"matched: E2E-X:<redacted len=26 sha=0123abcd>", ""},
		{"", ""},
	} {
		if got := displayReason(tc.in); got != tc.want {
			t.Errorf("displayReason(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
