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

//go:build !windows

package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

func TestToolCallHooksClassify(t *testing.T) {
	const none, ran, failed, refused = toolResultNone, toolResultRan, toolResultFailed, toolResultRefused
	type row struct {
		connector, event, status string
		pre                      bool
		result                   toolResult
	}
	for _, tt := range []row{
		// A decision that names no connector reads Claude Code's events.
		{"", "PreToolUse", "", true, none}, {"", "PostToolUse", "", false, ran}, {"", "PostToolUseFailure", "", false, failed},
		{"", "PermissionDenied", "", false, refused}, {"claudecode", "PreToolUse", "", true, none}, {"claudecode", "PostToolUse", "", false, ran},
		{"claudecode", "PostToolUseFailure", "", false, failed}, {"claudecode", "PermissionDenied", "", false, refused},
		{"codex", "PreToolUse", "", true, none}, {"codex", "PostToolUse", "", false, ran},
		{"cursor", "preToolUse", "", true, none}, {"cursor", "postToolUse", "", false, ran}, {"cursor", "postToolUseFailure", "", false, failed},
		{"opencode", "tool.execute.before", "", true, none}, {"opencode", "tool.execute.after", "", false, ran},
		{"opencode", "tool.execute.after", "done", false, ran}, {"amp", "tool.call", "", true, none}, {"amp", "tool.result", "done", false, ran},
		{"amp", "tool.result", " done ", false, ran}, {"amp", "tool.result", "error", false, failed}, {"amp", "tool.result", "cancelled", false, failed},
		{"amp", "tool.result", "", false, failed}, {"amp", "tool.result", "Done", false, failed}, {"amp", "agent.end", "done", false, none},
		{"kiro", "preToolUse", "", true, none}, {"kiro", "postToolUse", "", false, ran},
		{"copilot", "preToolUse", "", true, none}, {"copilot", "postToolUse", "", false, ran}, {"copilot", "postToolUseFailure", "", false, failed},
		{"devin", "PreToolUse", "", true, none}, {"devin", "PostToolUse", "", false, ran},
		{"hermes", "pre_tool_call", "", true, none}, {"hermes", "post_tool_call", "", false, ran}, {"openhands", "PreToolUse", "", true, none},
		{"antigravity", "PostToolUse", "", false, ran}, {"omnigent", "PreToolUse", "", true, none},
		// Exact vendor spellings of each harness only; a connector with no reviewed hooks names nothing.
		{"", "preToolUse", "", false, none}, {"claudecode", "post_tool_use", "", false, none}, {"claudecode", "PermissionRequest", "", false, none},
		{"claudecode", "PostToolBatch", "", false, none}, {"claudecode", "SessionStart", "", false, none}, {"codex", "PermissionDenied", "", false, none},
		{"cursor", "PreToolUse", "", false, none}, {"cursor", "beforeShellExecution", "", false, none}, {"cursor", "afterShellExecution", "", false, none},
		{"kiro", "PreToolUse", "", false, none}, {"kiro", "userPromptSubmit", "", false, none}, {"kiro", "stop", "", false, none},
		{"kiro", "", "", false, none}, {"copilot", "permissionRequest", "", false, none}, {"hermes", "PreToolUse", "", false, none},
		{"future", "PreToolUse", "", false, none},
	} {
		if pre, result := toolCallHooksFor(tt.connector).classify(tt.event, tt.status); pre != tt.pre || result != tt.result {
			t.Errorf("%s: classify(%q, %q) = %v, %v; want %v, %v", tt.connector, tt.event, tt.status, pre, result, tt.pre, tt.result)
		}
	}
	// Each sandboxed harness's pre-tool event counts as one tool call, nothing else.
	for event, want := range map[string]bool{"PreToolUse": true, "preToolUse": true, "tool.execute.before": true, "tool.call": true, "pre_tool_call": true,
		"PostToolUse": false, "postToolUse": false, "tool.execute.after": false, "tool.result": false, "beforeShellExecution": false, "UserPromptSubmit": false, "": false} {
		if isToolEvent(event) != want {
			t.Errorf("isToolEvent(%q) = %v", event, !want)
		}
	}
}

// Every sandboxed harness is listed, and each pairs by the identity its
// hooks carry: a per-call ID, the call's content (Kiro CLI, Copilot CLI and
// Devin CLI send none the gateway reads), or nothing (harnesses whose
// post-tool events on a denied call are unmeasured).
func TestToolCallHooksKeying(t *testing.T) {
	want := map[string]toolCallKeying{
		"claudecode": keyByID, "codex": keyByID, "cursor": keyByID, "opencode": keyByID, "amp": keyByID, "kiro": keyByContent,
		"copilot": keyByContent, "devin": keyByContent, "hermes": keyNone, "openhands": keyNone, "antigravity": keyNone, "omnigent": keyNone,
	}
	if len(toolCallHooksByConnector) != len(want) {
		t.Fatalf("toolCallHooksByConnector lists %d connectors, want %d", len(toolCallHooksByConnector), len(want))
	}
	for name, keying := range want {
		if hooks, ok := toolCallHooksByConnector[name]; !ok || hooks.keying != keying || hooks.pre == "" || (hooks.ran == "" && hooks.statusResult == "") {
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
	if long := idRef(strings.Repeat("x", 4096)); !strings.HasPrefix(long.key, "sha256:") || len(long.key) > 80 {
		t.Fatalf("oversized ID = %q", long.key)
	}
	input := json.RawMessage(`{"command":"echo a","cwd":"/work"}`)
	a := contentRef("sess-1", "shell", input)
	if !a.byContent || !strings.HasPrefix(a.key, "call:") {
		t.Fatalf("contentRef = %+v", a)
	}
	// The same call spelled with other whitespace and key order.
	if b := contentRef(" sess-1 ", " shell ", json.RawMessage("{ \"cwd\": \"/work\",\n \"command\": \"echo a\" }")); b != a {
		t.Fatalf("equivalent input keyed %q, want %q", b.key, a.key)
	}
	for name, other := range map[string]toolCallRef{
		"input": contentRef("sess-1", "shell", json.RawMessage(`{"command":"echo b","cwd":"/work"}`)),
		"tool":  contentRef("sess-1", "fs_read", input), "session": contentRef("sess-2", "shell", input),
		"boundary": contentRef("sess-1s", "hell", input), // moving a byte across fields changes the key
		"number":   contentRef("sess-1", "shell", json.RawMessage(`{"n":12345678901234567891}`)),
	} {
		if other.key == a.key {
			t.Errorf("%s: a different call shares the key", name)
		}
	}
	// Numbers are kept verbatim, not rounded through float64.
	if contentRef("s", "t", json.RawMessage(`{"n":12345678901234567891}`)) == contentRef("s", "t", json.RawMessage(`{"n":12345678901234567892}`)) {
		t.Error("large numbers that differ share a key")
	}
	for _, missing := range []toolCallRef{contentRef("sess-1", "", input), contentRef("sess-1", "shell", nil), contentRef("sess-1", "shell", json.RawMessage("  "))} {
		if missing.key != "" {
			t.Errorf("a call without a tool or input named %+v", missing)
		}
	}
	if contentRef("s", "t", json.RawMessage("not json")).key == "" {
		t.Error("non-JSON input named no call")
	}
}

// The ledger's verdicts for ID-keyed calls and for content keys, which
// identical calls share (Kiro CLI sends no per-call ID): the ledger counts
// open calls, and a later call's own verdict decides.
func TestHookTamperTrackerVerdicts(t *testing.T) {
	type step struct {
		pre, denied bool
		result      toolResult
		want        tamperKind
	}
	pre, deny := step{pre: true}, step{pre: true, denied: true}
	ranOK, failed := step{result: toolResultRan}, step{result: toolResultFailed}
	ranUnseen, ranDenied := step{result: toolResultRan, want: tamperUnseen}, step{result: toolResultRan, want: tamperDenied}
	for _, tt := range []struct {
		name    string
		keys    string // "id", "content" or "" for both
		partial bool   // a ledger this process did not begin (adopted after a restart)
		steps   []step
	}{
		{"allowed then ran", "", false, []step{pre, ranOK}},
		{"denied then ran", "", false, []step{deny, ranDenied}},
		{"never seen then ran", "", false, []step{ranUnseen}},
		// A partial ledger cannot prove a call was never seen, but knows its own denials.
		{"partial: never seen then ran", "", true, []step{ranOK}},
		{"partial: denied then ran", "", true, []step{deny, ranDenied}},
		{"repeated result is reported once", "id", false, []step{ranUnseen, ranOK}},
		{"denied result reported once", "id", false, []step{deny, ranDenied, ranOK}},
		{"allowed result repeated", "id", false, []step{pre, ranOK, ranOK}},
		// Claude reports a failure before PreToolUse ran (invalid input) and its own refusals.
		{"failure without pre", "id", false, []step{failed}},
		{"refusal without pre", "id", false, []step{{result: toolResultRefused}}},
		{"denied then failure", "id", false, []step{deny, failed}},
		{"denied, failure, then ran", "id", false, []step{deny, failed, ranDenied}},
		{"a later allowed pre cannot clear a denial", "id", false, []step{deny, pre, ranDenied}},
		{"two identical calls, both paired", "content", false, []step{pre, pre, ranOK, ranOK}},
		// The second identical call's pre-tool hook was killed, but exactly this call was allowed.
		{"repeat of an allowed call", "content", false, []step{pre, ranOK, ranOK}},
		// The agent retried a denied call and DefenseClaw allowed it the second time.
		{"denied, then allowed, then ran", "content", false, []step{deny, pre, ranOK}},
		{"allowed, ran, denied, then ran", "content", false, []step{pre, ranOK, deny, ranDenied}},
		{"denied twice then ran", "content", false, []step{deny, deny, ranDenied, ranOK}},
		{"denied while an identical call is open", "content", false, []step{pre, deny, ranOK, ranOK}},
		{"failure closes one open call", "content", false, []step{pre, pre, failed, ranOK, ranOK}},
	} {
		for keys, call := range map[string]toolCallRef{"id": idRef("toolu_1"), "content": contentRef("sess-1", "shell", json.RawMessage(`{"command":"echo dctamper"}`))} {
			if tt.keys != "" && tt.keys != keys {
				continue
			}
			t.Run(keys+"/"+tt.name, func(t *testing.T) {
				tr := newHookTamperTracker()
				if !tt.partial {
					tr.Begin("b1")
				}
				for i, s := range tt.steps {
					if s.pre {
						tr.ObservePre("b1", call, s.denied)
					} else if got := tr.ObserveResult("b1", call, s.result); got != s.want {
						t.Fatalf("step %d: verdict %v, want %v", i, got, s.want)
					}
				}
			})
		}
	}
}

// The ledger stays bounded, and a long-running call pushed out of the open
// set by newer calls is remembered as seen: its result is no tamper.
func TestHookTamperTrackerIsBounded(t *testing.T) {
	echo := func(i int) toolCallRef {
		return contentRef("s", "shell", json.RawMessage(fmt.Sprintf(`{"command":"echo %d"}`, i)))
	}
	for _, keys := range []struct {
		name  string
		ref   func(int) toolCallRef
		calls int // identical open calls of the long-running one
	}{{"id", func(i int) toolCallRef { return idRef(fmt.Sprintf("toolu_%d", i)) }, 1}, {"content", echo, 2}} {
		name, ref := keys.name, keys.ref
		tr := newHookTamperTracker()
		tr.Begin("b1")
		for range keys.calls {
			tr.ObservePre("b1", ref(-1), false)
		}
		for i := range maxOpenToolCalls {
			tr.ObservePre("b1", ref(i), false)
		}
		if got := tr.ObserveResult("b1", ref(-1), toolResultRan); got != tamperNone {
			t.Fatalf("%s: evicted open call = %v", name, got)
		}
	}
	tr := newHookTamperTracker()
	tr.Begin("b1")
	long := strings.Repeat("x", 4096) // kept as its digest, and still pairs
	tr.ObservePre("b1", idRef(long), false)
	if tr.ObserveResult("b1", idRef(long), toolResultRan) != tamperNone {
		t.Fatal("oversized ID did not pair")
	}
	for i := range 5 * (maxOpenToolCalls + maxPastToolCalls) {
		id := fmt.Sprintf("toolu_%d", i)
		tr.ObservePre("b1", idRef(id), i%3 == 0)
		if i%2 == 0 {
			tr.ObserveResult("b1", idRef(id), toolResultRan)
		}
	}
	for i := range 5 * maxPastToolCalls {
		tr.ObserveResult("b1", idRef(fmt.Sprintf("unseen_%d", i)), toolResultRan)
	}
	for i := range 3 * maxOpenToolCalls {
		tr.ObservePre("b1", echo(i), false)
		tr.ObservePre("b1", echo(i), false)
	}
	n, _ := tr.tracked("b1")
	tr.mu.Lock()
	open, past := tr.bindings["b1"].open.Len(), tr.bindings["b1"].past.Len()
	tr.mu.Unlock()
	if open > maxOpenToolCalls || past > maxPastToolCalls || open+past != n {
		t.Fatalf("open %d past %d tracked %d, bounds %d and %d", open, past, n, maxOpenToolCalls, maxPastToolCalls)
	}
}

func TestHookTamperTrackerLedgers(t *testing.T) {
	tr := newHookTamperTracker()
	tr.Begin("b1")
	tr.ObservePre("b1", idRef(""), true)
	if tr.ObserveResult("b1", idRef(""), toolResultRan) != tamperNone || tr.ObserveResult("", idRef("toolu_1"), toolResultRan) != tamperNone {
		t.Fatal("a result without a tool-use ID or a binding was judged")
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
	tr.Forget("b1")
	if _, ok := tr.tracked("b1"); ok {
		t.Fatal("ledger survived Forget")
	}
	// Begin starts over: an earlier session's denial is gone.
	tr.ObservePre("b2", idRef("toolu_1"), true)
	tr.Begin("b2")
	if got := tr.ObserveResult("b2", idRef("toolu_1"), toolResultRan); got != tamperUnseen {
		t.Fatalf("after Begin = %v, want unseen", got)
	}
	tr.ObservePre("b3", idRef("toolu_1"), false)
	tr.Retain(func(id string) bool { return id == "b3" })
	_, dead := tr.tracked("b2")
	_, live := tr.tracked("b3")
	if dead || !live {
		t.Fatalf("after Retain: dead binding kept %v, live binding kept %v", dead, live)
	}
}

func hookTamperFindings(e *harnessEnv) []audit.SandboxFindingEvent {
	return e.tel.findingsOf(audit.SandboxFindingHookTamper)
}

// decider builds the sandbox's hook decisions of one tool.
func (e *harnessEnv) decider(sandbox, tool string) func(event, id, action string) HookDecision {
	id := e.binding(sandbox).ID
	return func(event, toolUseID, action string) HookDecision {
		return HookDecision{BindingID: id, SandboxName: sandbox, Event: event, Tool: tool, ToolUseID: toolUseID, Action: action}
	}
}

// For every harness whose hooks name a call, a killed pre-tool hook and a
// denied call that ran anyway are reported once (hooks.on_tamper: alert keeps
// the sandbox running); never for one whose hooks do not.
func TestHookTamperPerHarness(t *testing.T) {
	for _, tc := range []struct {
		connector, pre, post, status string
		byContent                    bool // no per-call ID (Kiro CLI, Copilot CLI, Devin CLI)
		paired                       bool
	}{
		{connector: "claudecode", pre: "PreToolUse", post: "PostToolUse", paired: true},
		{connector: "codex", pre: "PreToolUse", post: "PostToolUse", paired: true},
		{connector: "cursor", pre: "preToolUse", post: "postToolUse", paired: true},
		{connector: "opencode", pre: "tool.execute.before", post: "tool.execute.after", paired: true},
		{connector: "amp", pre: "tool.call", post: "tool.result", status: "done", paired: true},
		{connector: "kiro", pre: "preToolUse", post: "postToolUse", byContent: true, paired: true},
		{connector: "copilot", pre: "preToolUse", post: "postToolUse", byContent: true, paired: true},
		{connector: "devin", pre: "PreToolUse", post: "PostToolUse", byContent: true, paired: true},
		{connector: "hermes", pre: "pre_tool_call", post: "post_tool_call"},
		{connector: "openhands", pre: "PreToolUse", post: "PostToolUse"},
		{connector: "antigravity", pre: "PreToolUse", post: "PostToolUse"},
		{connector: "omnigent", pre: "PreToolUse", post: "PostToolUse"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			e, name := newEnv(t, nil), "tamper"+tc.connector
			if sb := e.create(sandboxapi.CreateRequest{Name: name}); sb.Pack != packs.DefaultPack {
				t.Fatalf("pack = %q", sb.Pack)
			}
			base := e.decider(name, "shell")
			d := func(event, action, call string) HookDecision {
				out := base(event, "call_"+call, action)
				out.Connector, out.SessionID, out.ToolInput = tc.connector, "sess-1", json.RawMessage(`{"command":"echo dctamper-`+call+`"}`)
				if tc.byContent {
					out.ToolUseID = ""
				}
				if event == tc.post {
					out.ResultStatus = tc.status
				}
				return out
			}
			for _, dec := range []HookDecision{d(tc.pre, "allow", "ok"), d(tc.post, "allow", "ok"), // paired: no tamper
				d(tc.post, "allow", "killed"), d(tc.pre, "block", "denied"), d(tc.post, "allow", "denied"),
				d(tc.post, "allow", "killed")} { // a replayed result is not reported again
				e.m.ObserveHookDecision(dec)
			}
			if tc.connector == "claudecode" { // a harness-reported failure and refusal prove nothing ran
				e.m.ObserveHookDecision(d("PostToolUseFailure", "allow", "fail"))
				e.m.ObserveHookDecision(d("PermissionDenied", "allow", "refused"))
			}
			findings := hookTamperFindings(e)
			if !tc.paired {
				if len(findings) != 0 {
					t.Fatalf("%s calls are not paired, but raised %+v", tc.connector, findings)
				}
				return
			}
			if len(findings) != 2 || !strings.Contains(findings[0].Title, "without a DefenseClaw verdict") ||
				!strings.Contains(findings[0].Description, "its "+tc.pre+" hook never reached DefenseClaw") || !strings.Contains(findings[0].Evidence, "event="+tc.post) ||
				!strings.Contains(findings[1].Title, "denied ran anyway") || !strings.Contains(findings[1].Description, "denied its "+tc.pre) {
				t.Fatalf("hook tamper findings = %+v", findings)
			}
			if ev := findings[0].Evidence; tc.byContent == strings.Contains(ev, "tool_use_id=") || !tc.byContent && !strings.Contains(ev, "tool_use_id=call_killed") {
				t.Fatalf("evidence %q: a tool_use_id belongs to ID-keyed calls only", findings[0].Evidence)
			}
			for _, f := range findings {
				if f.Severity != "HIGH" || f.Sandbox.Name != name || f.TargetRef != name || !strings.Contains(f.Remediation, "hooks.on_tamper: alert") ||
					!strings.Contains(f.Evidence, "tool=shell") {
					t.Fatalf("finding = %+v", f)
				}
			}
			feed := e.events(name, sandboxapi.ActivityFinding, string(audit.SandboxFindingHookTamper))
			if len(feed) != 2 || feed[0].Severity != "HIGH" || feed[0].Tool != "shell" || !strings.Contains(feed[0].Message, "keeps running") {
				t.Fatalf("feed = %+v", feed)
			}
			// The denied pre-tool call still counts as a blocked tool call.
			if got := e.get(name); got.Phase != "ready" || got.Hooks.Tampered != 2 || got.Hooks.LastTamperAt.IsZero() ||
				got.Hooks.ToolBlocked != 1 || got.Hooks.ToolCalls != 2 {
				t.Fatalf("phase %s hooks %+v", got.Phase, got.Hooks)
			}
			if tc.connector == "amp" {
				// A tool.result that is not done closes even a denied call without proving it ran.
				refused := d(tc.post, "allow", "refused")
				refused.ResultStatus = "cancelled"
				e.m.ObserveHookDecision(d(tc.pre, "block", "refused"))
				e.m.ObserveHookDecision(refused)
				if len(hookTamperFindings(e)) != 2 {
					t.Fatalf("a cancelled tool.result raised %+v", hookTamperFindings(e)[2:])
				}
			}
			if tc.connector == "copilot" {
				// A postToolUseFailure closes even a denied call without
				// proving it ran, and identical calls pair one by one.
				e.m.ObserveHookDecision(d(tc.pre, "block", "failed"))
				e.m.ObserveHookDecision(d("postToolUseFailure", "allow", "failed"))
				for _, dec := range []HookDecision{d(tc.pre, "allow", "twice"), d(tc.pre, "allow", "twice"),
					d(tc.post, "allow", "twice"), d(tc.post, "allow", "twice")} {
					e.m.ObserveHookDecision(dec)
				}
				if len(hookTamperFindings(e)) != 2 {
					t.Fatalf("a postToolUseFailure or an identical call pair raised %+v", hookTamperFindings(e)[2:])
				}
			}
			if tc.connector == "devin" {
				// As measured on Devin CLI 3000.11.3: a tool that failed
				// before it ran sends no PostToolUse, so its call stays
				// open, and an identical call after it pairs; parallel
				// identical calls pair one by one; a command the user
				// edits at Devin's permission prompt gets a new PreToolUse
				// with the edited input, and only that one's PostToolUse
				// arrives.
				edited := d(tc.pre, "allow", "edited")
				edited.ToolInput = json.RawMessage(`{"command":"echo dctamper-edited-by-the-user"}`)
				editedRan := edited
				editedRan.Event = tc.post
				for _, dec := range []HookDecision{d(tc.pre, "allow", "failed"),
					d(tc.pre, "allow", "failed"), d(tc.post, "allow", "failed"),
					d(tc.pre, "allow", "twice"), d(tc.pre, "allow", "twice"), d(tc.post, "allow", "twice"), d(tc.post, "allow", "twice"),
					d(tc.pre, "allow", "edited"), edited, editedRan} {
					e.m.ObserveHookDecision(dec)
				}
				if len(hookTamperFindings(e)) != 2 {
					t.Fatalf("a failed, identical or edited Devin call raised %+v", hookTamperFindings(e)[2:])
				}
				// An edited command whose PreToolUse DefenseClaw denied,
				// and that ran anyway, is still reported.
				denied := d(tc.pre, "block", "edited-denied")
				denied.ToolInput = json.RawMessage(`{"command":"echo dctamper-edited-and-denied"}`)
				deniedRan := denied
				deniedRan.Event, deniedRan.Action = tc.post, "allow"
				for _, dec := range []HookDecision{d(tc.pre, "allow", "edited-denied"), denied, deniedRan} {
					e.m.ObserveHookDecision(dec)
				}
				if got := hookTamperFindings(e); len(got) != 3 || !strings.Contains(got[2].Title, "denied ran anyway") {
					t.Fatalf("an edited Devin call DefenseClaw denied that ran anyway raised %+v", got[2:])
				}
			}
		})
	}
}

func stopped(t *testing.T, e *harnessEnv, name string) bool {
	t.Helper()
	e.m.tamperStops.Wait()
	got, _ := e.client.GetSandbox(t.Context(), name)
	return got != nil && got.Status.Phase == openshell.PhaseStopped
}

// Under hooks.on_tamper: stop a tampered sandbox is stopped once; a new
// session starts with a clean ledger and may be stopped again.
func TestHookTamperStop(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "tamperstop", Pack: "balanced"})
	d := e.decider("tamperstop", "Bash")
	e.m.ObserveHookDecision(d("PostToolUse", "toolu_1", "allow"))
	e.m.ObserveHookDecision(d("PostToolUse", "toolu_2", "allow"))
	if !stopped(t, e, "tamperstop") {
		t.Fatal("the tampered sandbox did not stop")
	}
	if f := hookTamperFindings(e); len(f) != 2 || !strings.Contains(f[0].Remediation, "hooks.on_tamper: stop") {
		t.Fatalf("findings = %+v", f)
	}
	feed := e.events("tamperstop", sandboxapi.ActivityFinding, string(audit.SandboxFindingHookTamper))
	if len(feed) != 2 || !strings.Contains(feed[0].Message, "stopping the sandbox") || !strings.Contains(feed[1].Message, "already stopping") {
		t.Fatalf("feed = %+v", feed)
	}
	if stops := where(&e.tel.mu, &e.tel.lifecycle, func(ev audit.SandboxLifecycleEvent) bool {
		return ev.Sandbox.Name == "tamperstop" && ev.Trigger == audit.SandboxTriggerStop && ev.Sandbox.Phase == audit.SandboxPhaseStopping
	}); len(stops) != 1 {
		t.Fatalf("stops = %d, want one", len(stops))
	}
	e.startBox("tamperstop", sandboxapi.StartRequest{})
	d = e.decider("tamperstop", "Bash")
	e.m.ObserveHookDecision(d("PreToolUse", "toolu_3", "allow"))
	e.m.ObserveHookDecision(d("PostToolUse", "toolu_3", "allow"))
	if e.get("tamperstop").Phase != "ready" {
		t.Fatal("a paired call stopped the sandbox")
	}
	e.m.ObserveHookDecision(d("PostToolUse", "toolu_4", "allow"))
	if !stopped(t, e, "tamperstop") {
		t.Fatal("the second session did not stop")
	}
}

// A decision for another binding of the name neither alarms nor leaves a
// ledger; a delete drops the ledger, and one a decision raced back is pruned.
func TestHookTamperIgnoresStaleBindingAndForgets(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "tamperstale"})
	id := e.binding("tamperstale").ID
	tracked := func(binding string) bool { _, ok := e.m.toolCalls.tracked(binding); return ok }
	e.m.ObserveHookDecision(HookDecision{BindingID: "sb_other", SandboxName: "tamperstale", Event: "PostToolUse", ToolUseID: "toolu_1"})
	if f := hookTamperFindings(e); len(f) != 0 || tracked("sb_other") {
		t.Fatalf("a stale binding raised %+v or got a ledger", f)
	}
	e.m.ObserveHookDecision(e.decider("tamperstale", "")("PreToolUse", "toolu_1", "allow"))
	if !tracked(id) {
		t.Fatal("no ledger for the live binding")
	}
	e.deleteBox("tamperstale", sandboxapi.DeleteRequest{})
	if tracked(id) {
		t.Fatal("the revoked binding's ledger survived the delete")
	}
	e.m.toolCalls.ObservePre(id, idRef("toolu_2"), false)
	e.m.pruneToolCalls()
	if tracked(id) {
		t.Fatal("prune kept a dead binding's ledger")
	}
}

// After a daemon restart the running sandbox's ledger is partial: a result
// for a call from before the restart is no tamper, a denial seen after it
// still is.
func TestHookTamperAfterRestart(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "tamperrestart", Pack: "balanced"})
	d := e.decider("tamperrestart", "Bash")
	e.m.ObserveHookDecision(d("PreToolUse", "toolu_before", "allow"))
	e.restartDaemon()
	e.m.ObserveHookDecision(d("PostToolUse", "toolu_before", "allow"))
	if len(hookTamperFindings(e)) != 0 {
		t.Fatalf("a call from before the restart raised %+v", hookTamperFindings(e))
	}
	e.m.ObserveHookDecision(d("PreToolUse", "toolu_after", "block"))
	e.m.ObserveHookDecision(d("PostToolUse", "toolu_after", "allow"))
	if f := hookTamperFindings(e); len(f) != 1 || !strings.Contains(f[0].Remediation, "hooks.on_tamper: stop") || !stopped(t, e, "tamperrestart") {
		t.Fatalf("denied call after the restart: %+v, want the adopted sandbox stopped", f)
	}
}

// Hook text is cut and stripped of control characters, and a redacted reason
// never reaches the feed.
func TestHookLabelAndDisplayReason(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Bash", "Bash"}, {" mcp__github__create_issue ", "mcp__github__create_issue"},
		{"a b\tc\n\x1b[31m\"\\", "abc[31m"}, {strings.Repeat("y", 100), strings.Repeat("y", 64)},
	} {
		if got := hookLabel(tc.in, 64); got != tc.want {
			t.Errorf("hookLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	plain := "Blocked by DefenseClaw rule CMD-1: Title. Do this instead."
	for _, tc := range []struct{ in, want string }{
		{plain, plain}, {"  plain  ", "plain"}, {"<redacted len=12 sha=0123abcd>", ""}, {"matched: E2E-X:<redacted len=26 sha=0123abcd>", ""}, {"", ""},
	} {
		if got := displayReason(tc.in); got != tc.want {
			t.Errorf("displayReason(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Hook requests and verdicts are counted, a block and an ask are on the feed,
// and only an alert verdict (ran, flagged) is a finding there; another
// binding's counts nothing.
func TestHookCoverage(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "hookbox"})
	binding, d := e.binding("hookbox"), e.decider("hookbox", "Bash")
	e.m.ObserveIngress(binding, sandboxauth.RouteHook)
	allow, block, alert, other := d("PreToolUse", "", "allow"), d("PreToolUse", "", "block"), d("PreToolUse", "", "alert"), d("PreToolUse", "", "block")
	ask := d("PreToolUse", "", "confirm")
	ask.Severity, ask.Reason = "HIGH", "DefenseClaw rule C2-WEBHOOK-SITE asks you to confirm this."
	allow.Severity, other.BindingID = "NONE", "sb_other"
	block.Severity, block.WouldBlock, block.Reason = "HIGH", true,
		"DefenseClaw policy blocked this action (rule E2E-SANDBOX-MARKER: E2E sandbox marker command). Do not retry it in another form."
	alert.Severity, alert.Reason = "high", "Allowed but flagged by DefenseClaw rule E2E-SANDBOX-ALERT: E2E sandbox alert marker. "+
		"The action was allowed; DefenseClaw recorded the finding for the user's review."
	for _, dec := range []HookDecision{allow, block, alert, ask, d("PostToolUse", "", "allow"), other} {
		e.m.ObserveHookDecision(dec)
	}
	if h := e.get("hookbox").Hooks; h.HookRequests != 1 || h.ToolCalls != 4 || h.ToolBlocked != 1 || h.ToolAsked != 1 || h.LastBlocked != block.Reason {
		t.Fatalf("hooks = %+v", h)
	}
	// An ask is on the feed as one, not as a finding.
	if got := e.events("hookbox", sandboxapi.ActivityToolAsked, ""); len(got) != 1 || got[0].Tool != "Bash" ||
		got[0].Message != "? DefenseClaw asked you to confirm Bash: "+ask.Reason {
		t.Fatalf("tool asks on the feed = %+v", got)
	}
	if got := e.events("hookbox", sandboxapi.ActivityToolBlocked, ""); len(got) != 1 || got[0].Tool != "Bash" ||
		got[0].Message != "✗ Bash blocked by DefenseClaw: E2E-SANDBOX-MARKER (E2E sandbox marker command)" ||
		got[0].Reason != block.Reason {
		t.Fatalf("tool blocks on the feed = %+v", got)
	}
	findings := e.events("hookbox", sandboxapi.ActivityFinding, sandboxapi.ReasonHookFinding)
	if len(findings) != 1 || findings[0].Severity != "HIGH" || findings[0].Tool != "Bash" ||
		findings[0].Message != "⚠ Bash allowed but flagged by DefenseClaw: E2E-SANDBOX-ALERT (E2E sandbox alert marker)" {
		t.Fatalf("finding events = %+v", findings)
	}
	// A blocked prompt is on the feed and counted, but is no tool call
	// (GAP-1791). Its line names the rule, not the whole reason with the
	// advice to the agent (GAP-1902).
	prompt := d("UserPromptSubmit", "", "block")
	prompt.Tool, prompt.Severity, prompt.Reason = "", "CRITICAL",
		"DefenseClaw policy blocked this action (rule SEC-AWS-KEY: AWS access key). Do not retry it in another form."
	e.m.ObserveHookDecision(prompt)
	e.m.ObserveHookDecision(d("UserPromptSubmit", "", "allow"))
	if h := e.get("hookbox").Hooks; h.ToolCalls != 4 || h.ToolBlocked != 1 || h.PromptBlocked != 1 {
		t.Fatalf("hooks after a prompt block = %+v", h)
	}
	if got := e.events("hookbox", sandboxapi.ActivityHookBlocked, ""); len(got) != 1 || got[0].Severity != "CRITICAL" ||
		got[0].Message != "✗ prompt blocked by DefenseClaw: SEC-AWS-KEY (AWS access key)" || got[0].Reason != prompt.Reason {
		t.Fatalf("prompt blocks on the feed = %+v", got)
	}
}

// Every verdict counts under its hook event, the harness's name for it, tool
// events or not (#956). The counts live as long as the sandbox's other hook
// counters: a stop and start keep them, a new sandbox of the name and a
// daemon restart start over.
func TestHookEventCounts(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "eventbox"})
	d := e.decider("eventbox", "Bash")
	for _, dec := range []HookDecision{d("SessionStart", "", "allow"), d("UserPromptSubmit", "", "allow"),
		d("PreToolUse", "toolu_1", "allow"), d("PostToolUse", "toolu_1", "allow"), d("PreToolUse", "toolu_2", "block"),
		d("Stop", "", "allow"), {BindingID: "sb_other", SandboxName: "eventbox", Event: "PreToolUse"}} {
		e.m.ObserveHookDecision(dec)
	}
	want := map[string]int64{"SessionStart": 1, "UserPromptSubmit": 1, "PreToolUse": 2, "PostToolUse": 1, "Stop": 1}
	if h := e.get("eventbox").Hooks; !maps.Equal(h.Events, want) || h.OtherEvents != 0 || h.ToolCalls != 2 || h.ToolBlocked != 1 {
		t.Fatalf("hooks = %+v, want events %v", h, want)
	}
	e.stopBox("eventbox")
	e.startBox("eventbox", sandboxapi.StartRequest{})
	e.m.ObserveHookDecision(e.decider("eventbox", "Bash")("SessionStart", "", "allow"))
	want["SessionStart"]++
	if h := e.get("eventbox").Hooks; !maps.Equal(h.Events, want) {
		t.Fatalf("after a restart of the sandbox: events %v, want %v", h.Events, want)
	}
	e.restartDaemon()
	if h := e.get("eventbox").Hooks; h.Events != nil || h.HookRequests != 0 {
		t.Fatalf("after a daemon restart: hooks %+v, want no counts", h)
	}
	e.m.ObserveHookDecision(e.decider("eventbox", "Bash")("Stop", "", "allow"))
	e.deleteBox("eventbox", sandboxapi.DeleteRequest{})
	e.create(sandboxapi.CreateRequest{Name: "eventbox"})
	if h := e.get("eventbox").Hooks; h.Events != nil {
		t.Fatalf("a new sandbox of the name has events %v", h.Events)
	}

	// Another harness's names are its own (OpenCode's plugin events).
	e.create(sandboxapi.CreateRequest{Name: "eventoc", Project: e.otherProject("eventoc")})
	oc := e.decider("eventoc", "bash")
	for _, event := range []string{"session.created", "tool.execute.before", "tool.execute.after", "session.idle"} {
		dec := oc(event, "call_1", "allow")
		dec.Connector = "opencode"
		e.m.ObserveHookDecision(dec)
	}
	if h := e.get("eventoc").Hooks; !maps.Equal(h.Events, map[string]int64{
		"session.created": 1, "tool.execute.before": 1, "tool.execute.after": 1, "session.idle": 1,
	}) || h.ToolCalls != 1 {
		t.Fatalf("opencode hooks = %+v", h)
	}
}

// The event names come from the workload: they are cut and stripped, a
// sandbox keeps at most MaxHookEvents of them and counts the rest, and an
// event without a printable name, as "other events".
func TestHookEventCountsAreBounded(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "floodbox"})
	d := e.decider("floodbox", "")
	e.m.ObserveHookDecision(d("PreToolUse", "", "allow"))
	e.m.ObserveHookDecision(d(" Pre\x1b[31mTool\u202eUse\n", "", "allow")) // kept without its control characters
	e.m.ObserveHookDecision(d("\x1b\u202e \t", "", "allow"))
	e.m.ObserveHookDecision(d(strings.Repeat("e", 200), "", "allow"))
	for i := range sandboxapi.MaxHookEvents {
		e.m.ObserveHookDecision(d("junk"+strconv.Itoa(i), "", "allow"))
	}
	e.m.ObserveHookDecision(d("PreToolUse", "", "allow")) // a name it keeps still counts
	h := e.get("floodbox").Hooks
	if len(h.Events) != sandboxapi.MaxHookEvents || h.Events["Pre[31mToolUse"] != 1 || h.Events["PreToolUse"] != 2 ||
		h.Events[strings.Repeat("e", maxHookEventName)] != 1 {
		t.Fatalf("events = %v", h.Events)
	}
	// Kept: PreToolUse, the cleaned name, the cut one and all but 3 of the
	// junk names; those 3 and the unprintable name count as other events.
	if h.OtherEvents != 4 {
		t.Fatalf("other events = %d, want 4", h.OtherEvents)
	}
	for name := range h.Events {
		if name != hookLabel(name, maxHookEventName) || len(name) > maxHookEventName {
			t.Fatalf("event name %q was kept as sent", name)
		}
	}
}

// Every harness's hook contract has fewer events than a sandbox keeps
// counts for, so a harness's own events never fall into "other events".
func TestHookEventCapCoversEveryContract(t *testing.T) {
	for name := range toolCallHooksByConnector {
		for _, c := range connector.KnownHookContracts(name) {
			if len(c.Events) >= sandboxapi.MaxHookEvents {
				t.Errorf("%s contract %s has %d events, MaxHookEvents is %d", name, c.ContractID, len(c.Events), sandboxapi.MaxHookEvents)
			}
		}
	}
}

// The harness at work for silence_after since its last hook raises one
// hook_silence finding until the next hook. Commands it did not run, an idle
// harness, one that wakes for a moment after a long idle stretch, and work
// broken by an idle stretch that long never do.
func TestHookSilenceCountsOnlyTheHarness(t *testing.T) {
	e := newEnv(t, nil)
	now, advance := e.fakeClock(time.Now())
	e.create(sandboxapi.CreateRequest{Name: "quietbox"})
	b := e.boxOf("quietbox")
	silence := func() int {
		e.m.checkHookSilence(t.Context())
		return len(e.tel.findingsOf(audit.SandboxFindingHookSilence))
	}
	// work feeds r now and then once a minute for the given minutes.
	work := func(minutes int, r ocsf.Record) int {
		e.m.ocsfEvent(t.Context(), b, r, now())
		for range minutes {
			advance(time.Minute)
			e.m.ocsfEvent(t.Context(), b, r, now())
		}
		return silence()
	}
	for range 16 {
		advance(time.Minute)
		e.m.ocsfEvent(t.Context(), b, ocsf.Record{Class: ocsf.ClassProcess, Binary: "/usr/bin/git"}, now())
		e.m.ocsfEvent(t.Context(), b, ocsf.Record{Class: ocsf.ClassNetwork, Binary: "/usr/bin/curl", Host: "example.org", Port: 443}, now())
		e.m.ocsfEvent(t.Context(), b, ocsf.Record{Class: ocsf.ClassNetwork, Binary: "/opt/defenseclaw-harness-evil/bin/claude", Host: "example.org", Port: 443}, now())
		// Certification AG-MAC-F4: a `sandbox exec` curl through the egress
		// proxy, with no harness running, raised the alarm. Neither the
		// proxy's own events nor OpenShell's record of curl's connection to
		// the proxy are the harness's.
		e.m.ocsfEvent(t.Context(), b, ocsf.Record{Class: ocsf.ClassNetwork, Binary: "/usr/bin/curl", Host: openshellHostAlias, Port: testEgressPort,
			Action: ocsf.ActionAllowed, Policy: "defenseclaw_egress"}, now())
		e.m.egressEvent(t.Context(), egress.Event{Kind: egress.EventAllowed, SandboxName: "quietbox", Host: "example.org", Port: 443, Time: now(), FirstSeen: true}, 0)
		e.m.egressEvent(t.Context(), egress.Event{Kind: egress.EventClosed, SandboxName: "quietbox", Host: "example.org", Port: 443, Time: now()}, 0)
	}
	if n := silence(); n != 0 {
		t.Fatalf("commands outside the harness raised %d hook_silence finding(s)", n)
	}
	// The harness's own connection to the proxy is its activity. Idle for
	// 16 minutes, it wakes (a harness such as Kiro CLI sends no hook when it
	// starts): one event is no work without hooks, and neither is work cut
	// by an idle stretch of silence_after.
	proxy := ocsf.Record{Class: ocsf.ClassNetwork, Binary: testClaudeBin, Host: openshellHostAlias, Port: testEgressPort,
		Action: ocsf.ActionAllowed, Policy: "defenseclaw_egress"}
	if work(0, proxy) != 0 || work(5, proxy) != 0 {
		t.Fatal("a harness that woke after an idle stretch raised hook_silence")
	}
	advance(10 * time.Minute)
	if work(5, proxy) != 0 || e.get("quietbox").Hooks.Silent {
		t.Fatal("work broken by an idle stretch of silence_after raised hook_silence")
	}
	if work(5, proxy) != 1 || silence() != 1 || !e.get("quietbox").Hooks.Silent {
		t.Fatal("the harness at work for silence_after without hooks raised no single hook_silence finding")
	}
	if f := e.tel.findingsOf(audit.SandboxFindingHookSilence); !strings.Contains(f[0].Description, "doing work for 10m0s") {
		t.Fatalf("description = %q, want the 10 minutes of work", f[0].Description)
	}
	e.m.ObserveIngress(e.binding("quietbox"), sandboxauth.RouteHook)
	advance(15 * time.Minute)
	model := ocsf.Record{Class: ocsf.ClassNetwork, Binary: testClaudeBin, Host: "api.anthropic.com", Port: 443}
	if work(0, model) != 1 {
		t.Fatal("a harness that woke long after its last hook raised hook_silence")
	}
	if work(10, model) != 2 || !e.get("quietbox").Hooks.Silent {
		t.Fatal("the harness at work long after its last hook raised no second hook_silence finding")
	}
	e.m.ObserveIngress(e.binding("quietbox"), sandboxauth.RouteHook)
	if e.get("quietbox").Hooks.Silent {
		t.Fatal("a hook did not clear the silence")
	}
	advance(time.Hour)
	if silence() != 2 {
		t.Fatal("an idle harness raised a finding")
	}
}

// Under hooks.on_silence: stop (balanced, strict) a user-tier harness that
// works for the pack's hooks.silence_after without one hook is stopped, as a
// tampered one is, and its next session is watched again; under alert (open)
// it keeps running, and a managed-tier harness only alerts whatever the pack
// says. A harness that wakes for a moment after an idle stretch longer than
// silence_after is neither.
func TestHookSilenceResponse(t *testing.T) {
	quick := t.TempDir()
	writeFile(t, filepath.Join(quick, "quick", "pack.yaml"), strings.Replace(strings.Replace(teamPack, "name: team", "name: quick", 1),
		"hooks: {fail_mode: closed}", "hooks: {fail_mode: closed, on_silence: stop, silence_after: 2m}", 1))
	for _, tc := range []struct {
		name, pack, tier, response, outcome string
		after                               time.Duration
	}{
		{"balanced user tier", "balanced", "user", "stop", "; stopping the sandbox (hooks.on_silence: stop)", 10 * time.Minute},
		{"strict user tier", "strict", "user", "stop", "; stopping the sandbox (hooks.on_silence: stop)", 10 * time.Minute},
		{"open user tier", "open", "user", "alert", "; the sandbox keeps running (hooks.on_silence: alert)", 10 * time.Minute},
		{"strict managed tier", "strict", "managed", "alert", "; the sandbox keeps running", 10 * time.Minute},
		{"a custom pack's silence_after", "quick", "user", "stop", "; stopping the sandbox (hooks.on_silence: stop)", 2 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = quick })
			now, advance := e.fakeClock(time.Now())
			e.create(sandboxapi.CreateRequest{Name: "silentbox", Pack: tc.pack})
			b := e.boxOf("silentbox")
			e.m.mu.Lock()
			b.rec.TamperTier = tc.tier
			e.m.mu.Unlock()
			after := packs.ShortDuration(tc.after)
			if h := e.get("silentbox").Hooks; h.OnSilence != tc.response || h.SilenceAfter != after {
				t.Fatalf("hooks = %+v, want on_silence %s after %s", h, tc.response, after)
			}
			findings := func() []audit.SandboxFindingEvent {
				e.m.checkHookSilence(t.Context())
				return e.tel.findingsOf(audit.SandboxFindingHookSilence)
			}
			// work keeps the harness busy for d, an event a minute from now.
			work := func(d time.Duration) []audit.SandboxFindingEvent {
				e.m.ocsfEvent(t.Context(), b, ocsf.Record{Class: ocsf.ClassNetwork, Binary: testClaudeBin, Host: "api.anthropic.com", Port: 443}, now())
				for range int(d / time.Minute) {
					advance(time.Minute)
					e.m.ocsfEvent(t.Context(), b, ocsf.Record{Class: ocsf.ClassNetwork, Binary: testClaudeBin, Host: "api.anthropic.com", Port: 443}, now())
				}
				return findings()
			}
			// Ready but idle for longer than silence_after, then the
			// harness's first event (Kiro CLI sends no hook when it starts).
			advance(tc.after + time.Minute)
			if f := work(0); len(f) != 0 || stopped(t, e, "silentbox") {
				t.Fatalf("a harness that woke after an idle stretch: findings %+v, stopped %v", f, stopped(t, e, "silentbox"))
			}
			advance(tc.after)
			if f := work(tc.after - time.Minute); len(f) != 0 {
				t.Fatalf("findings before silence_after: %+v", f)
			}
			f := work(time.Minute)
			feed := e.events("silentbox", sandboxapi.ActivityFinding, string(audit.SandboxFindingHookSilence))
			if len(f) != 1 || f[0].Evidence != "on_silence="+tc.response+" silence_after="+after+" tier="+tc.tier ||
				len(feed) != 1 || !strings.HasSuffix(feed[0].Message, tc.outcome) {
				t.Fatalf("findings %+v, feed %+v", f, feed)
			}
			if got := stopped(t, e, "silentbox"); got != (tc.response == "stop") {
				t.Fatalf("stopped = %v, want %v", got, tc.response == "stop")
			}
			if tc.response != "stop" {
				return
			}
			e.startBox("silentbox", sandboxapi.StartRequest{})
			advance(time.Minute)
			if f := work(tc.after); len(f) != 2 || !stopped(t, e, "silentbox") {
				t.Fatalf("the next silent session: findings %+v, stopped %v", f, stopped(t, e, "silentbox"))
			}
		})
	}
}

// Every hook post the ingress answered with an error counts (the hook failed
// closed, so the harness's action was blocked); the feed reports the first at
// once and then at most one summary per interval.
func TestHookFailuresCountedAndReported(t *testing.T) {
	e := newEnv(t, nil)
	now, advance := e.fakeClock(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))
	e.create(sandboxapi.CreateRequest{Name: "failbox"})
	id := e.binding("failbox").ID
	failures := func() []sandboxapi.ActivityEvent { return e.events("failbox", sandboxapi.ActivityHookFailed, "") }
	fail := func(status int) {
		e.m.ObserveHookFailure(HookFailure{BindingID: id, SandboxName: "failbox", Status: status})
	}
	// A stale binding (a rotated session) and another sandbox's name do not count.
	e.m.ObserveHookFailure(HookFailure{BindingID: "sb_old", SandboxName: "failbox", Status: 403})
	e.m.ObserveHookFailure(HookFailure{BindingID: id, SandboxName: "other", Status: 403})
	if got := e.get("failbox"); got.Hooks.HookFailed != 0 || len(failures()) != 0 {
		t.Fatalf("foreign failures counted: %+v", got.Hooks)
	}
	fail(400)
	if evs := failures(); len(evs) != 1 || evs[0].Reason != "HTTP 400 Bad Request" ||
		!strings.Contains(evs[0].Message, "a hook call failed (HTTP 400 Bad Request)") || !strings.Contains(evs[0].Message, "hooks fail closed") {
		t.Fatalf("first failure on the feed = %+v", evs)
	}
	for range 5 {
		advance(time.Second)
		fail(429)
	}
	if h := e.get("failbox").Hooks; h.HookFailed != 6 || h.LastHookFailure != "HTTP 429 Too Many Requests" || !h.LastHookFailureAt.Equal(now()) || len(failures()) != 1 {
		t.Fatalf("hooks = %+v, feed %+v; want the burst counted and off the feed", h, failures())
	}
	advance(hookFailureNoticeInterval)
	fail(429)
	if len(failures()) != 2 || !strings.Contains(failures()[1].Message, "6 hook calls failed (last: HTTP 429 Too Many Requests)") {
		t.Fatalf("summary on the feed = %+v", failures())
	}
	// Failures are not verdicts: the tool-call counters are untouched.
	if h := e.get("failbox").Hooks; h.HookFailed != 7 || h.ToolCalls != 0 || h.ToolBlocked != 0 {
		t.Fatalf("hooks = %+v", h)
	}
}

// reachEnv is a manager with one ready sandbox and a clock the test moves.
type reachEnv struct {
	*harnessEnv
	name    string
	binding sandboxauth.Binding
	advance func(time.Duration)
}

func newReachEnv(t *testing.T) *reachEnv {
	t.Helper()
	r := &reachEnv{harnessEnv: newEnv(t, nil), name: "reachbox"}
	_, r.advance = r.fakeClock(time.Now())
	r.create(sandboxapi.CreateRequest{Name: r.name})
	r.binding = r.harnessEnv.binding(r.name)
	return r
}

// line feeds one OpenShell shorthand line to the sandbox, stamped now.
func (r *reachEnv) line(s string) { r.ocsf(r.name, s, r.m.now()) }

func (r *reachEnv) hooks() sandboxapi.HookCoverage { return r.get(r.name).Hooks }

func (r *reachEnv) feed(reason string) []sandboxapi.ActivityEvent {
	return r.events(r.name, "", reason)
}

func (r *reachEnv) check() { r.m.checkHookReach(context.Background()) }

func (r *reachEnv) findings() []audit.SandboxFindingEvent {
	return where(&r.tel.mu, &r.tel.findings, func(f audit.SandboxFindingEvent) bool { return f.Title == "Sandbox hooks are not reaching DefenseClaw" })
}

func ingressLine(action string) string {
	return "NET:OPEN [MED] " + action + " /usr/bin/curl(7) -> host.openshell.internal:" + strconv.Itoa(testIngressPort) + " [policy:defenseclaw_ingress engine:opa]"
}

const modelCall = "NET:OPEN [INFO] ALLOWED " + testClaudeBin + "(9) -> api.anthropic.com:443 [policy:_provider_anthropic engine:opa]"

// OpenShell refusing the hooks' connections is reported at once, even after
// hooks that got through; an authenticated hook clears the flag, and the
// session is warned only once.
func TestHookReachRefusedConnections(t *testing.T) {
	r := newReachEnv(t)
	r.line(ingressLine("DENIED"))
	if h := r.hooks(); !h.Unreachable || h.IngressRefused != 1 || h.LastIngressRefusedAt.IsZero() ||
		!strings.Contains(h.UnreachableReason, "OpenShell refused") || !strings.Contains(h.UnreachableReason, strconv.Itoa(testIngressPort)) {
		t.Fatalf("hooks = %+v", h)
	}
	warn := r.feed(sandboxapi.ReasonHooksUnreachable)
	if len(warn) != 1 || warn[0].Severity != "HIGH" || warn[0].Kind != sandboxapi.ActivityFinding ||
		!strings.HasPrefix(warn[0].Message, "⚠ "+sandboxapi.HooksUnreachableWarning+" (OpenShell refused") || !strings.HasSuffix(warn[0].Message, sandboxapi.HooksDoctorHint) {
		t.Fatalf("feed = %+v", warn)
	}
	if f := r.findings(); len(f) != 1 || f[0].Kind != audit.SandboxFindingHookSilence || f[0].Severity != "HIGH" ||
		!strings.Contains(f[0].Remediation, "defenseclaw sandbox doctor") {
		t.Fatalf("findings = %+v", f)
	}
	r.advance(time.Second)
	r.m.ObserveIngress(r.binding, sandboxauth.RouteHook)
	if h := r.hooks(); h.Unreachable || h.UnreachableReason != "" || len(r.feed(sandboxapi.ReasonHooksRestored)) != 1 {
		t.Fatalf("a hook did not clear the flag: %+v", h)
	}
	// Hooks that break later in the session are flagged again, without a second warning.
	r.advance(time.Second)
	r.line(ingressLine("DENIED"))
	if h := r.hooks(); !h.Unreachable || h.IngressRefused != 2 || len(r.feed(sandboxapi.ReasonHooksUnreachable)) != 1 {
		t.Fatalf("hooks after a later refusal = %+v, want flagged with one warning per session", h)
	}
}

// A hook connection cut by a policy reload (a HIGH alarm live) is no refusal
// but an attempt: like an answered one, it is flagged only when no request
// authenticates within the grace period. So is a mapping denial of the
// ingress no settings reload explains, then as a refusal of its own.
func TestHookReachUnansweredConnections(t *testing.T) {
	ingress := strconv.Itoa(testIngressPort)
	for _, tc := range []struct {
		name, line, reason string
		refused            int64
	}{
		{"reload cut", "NET:OPEN [MED] DENIED host.openshell.internal:" + ingress +
			" [reason:L7 tunnel closed before inspection because policy changed: policy generation is stale [captured_generation:2 current_generation:3]]",
			"not one request authenticated", 0},
		{"allowed", ingressLine("ALLOWED"), "not one request authenticated", 0},
		{"mapping denial", "NET:OPEN [MED] DENIED " + testClaudeBin + "(0) -> host.openshell.internal:" + ingress + " [reason:transparent_tcp_mapping_denied]",
			"does not cover the port", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReachEnv(t)
			r.line(tc.line)
			r.advance(hookAttemptGrace - time.Second)
			r.check()
			if r.hooks().Unreachable || r.hooks().IngressRefused != 0 || len(r.feed(sandboxapi.ReasonHooksUnreachable)) != 0 {
				t.Fatalf("flagged within the grace period: %+v", r.hooks())
			}
			r.advance(2 * time.Second)
			r.check()
			if !r.hooks().Unreachable || r.hooks().NoHookYet || !strings.Contains(r.hooks().UnreachableReason, tc.reason) || r.hooks().IngressRefused != tc.refused {
				t.Fatalf("hooks = %+v", r.hooks())
			}
		})
	}
	// The client's next request answers a mapping denial: nothing is raised.
	r := newReachEnv(t)
	r.m.ObserveIngress(r.binding, sandboxauth.RouteHook)
	r.advance(time.Second)
	r.line("NET:OPEN [MED] DENIED " + testClaudeBin + "(0) -> host.openshell.internal:" + ingress + " [reason:transparent_tcp_mapping_denied]")
	r.advance(time.Second)
	r.m.ObserveIngress(r.binding, sandboxauth.RouteOTLP)
	r.advance(hookAttemptGrace + time.Second)
	r.check()
	if r.hooks().Unreachable || r.hooks().IngressRefused != 0 {
		t.Fatalf("a mapping denial the next request answered = %+v", r.hooks())
	}
	// A connection that gets through answers it too: the mapping covers the
	// port, and it is that connection's request that did not authenticate.
	r = newReachEnv(t)
	r.line("NET:OPEN [MED] DENIED " + testClaudeBin + "(0) -> host.openshell.internal:" + ingress + " [reason:transparent_tcp_mapping_denied]")
	r.advance(time.Second)
	r.line(ingressLine("ALLOWED"))
	r.advance(hookAttemptGrace + time.Second)
	r.check()
	if h := r.hooks(); !h.Unreachable || h.IngressRefused != 0 || !strings.Contains(h.UnreachableReason, "not one request authenticated") {
		t.Fatalf("a mapping denial a connection answered = %+v", h)
	}
}

// OpenShell reloads a running sandbox's settings whenever a gateway-global
// provider profile changes (a sandbox's --credential profile imported or
// deleted, by either daemon on the gateway) and maps the host alias again
// on the next lookup: a client connecting to the address it looked up
// before the reload (OpenCode's runtime keeps a lookup for 30 s) is denied
// its mapping. Seen live on an idle OpenCode's first plugin event and on a
// hook just before the harness quit, neither followed by a hook within the
// grace period: that is no refusal and no attempt. Past the reload's
// window, or once the mapping OpenShell reports leaves the port out (as
// when another daemon replaced the ingress profile), it is a refusal again.
func TestHookReachReloadMappingDenial(t *testing.T) {
	ingress := strconv.Itoa(testIngressPort)
	mapped := func(ports ...int) string {
		list := make([]string, len(ports))
		for i, p := range ports {
			list[i] = strconv.Itoa(p)
		}
		return "CONFIG:PUBLISHED [INFO] Policy DNS mapped host.openshell.internal resolved=127.0.0.1 synthetic=198.18.0.2 ports=" +
			strings.Join(list, ",") + " mapping_id=m1"
	}
	const reload = "CONFIG:DETECTED [INFO] Settings poll: config change detected [old_revision:7 new_revision:7 policy_changed:false provider_env_changed:true]"
	denied := "NET:OPEN [MED] DENIED " + testClaudeBin + "(0) -> 198.18.0.2:" + ingress + " [reason:transparent_tcp_mapping_denied]"
	idle := func(r *reachEnv) {
		for range 12 {
			r.advance(hookReachInterval)
			r.check()
		}
	}
	for _, tc := range []struct {
		name    string
		lines   []string
		gap     time.Duration // between the last line and the denial
		flagged bool
	}{
		{"after a provider reload", []string{mapped(testEgressPort, testIngressPort), reload}, 10 * time.Second, false},
		{"after a policy reload", []string{mapped(testIngressPort), strings.Replace(reload, "policy_changed:false", "policy_changed:true", 1)}, 0, false},
		{"long after a reload", []string{mapped(testEgressPort, testIngressPort), reload}, reloadMappingWindow + time.Second, true},
		{"no reload", []string{mapped(testEgressPort, testIngressPort)}, time.Second, true},
		{"a reload that changed nothing", []string{mapped(testIngressPort), strings.Replace(reload, "provider_env_changed:true", "provider_env_changed:false", 1)}, 0, true},
		{"the mapping leaves the port out", []string{reload, mapped(38971, 38972)}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReachEnv(t)
			for _, l := range tc.lines {
				r.line(l)
				r.advance(time.Second)
			}
			r.advance(tc.gap)
			r.line(denied)
			idle(r)
			h := r.hooks()
			if !tc.flagged {
				if h.Unreachable || h.IngressRefused != 0 || len(r.feed(sandboxapi.ReasonHooksUnreachable)) != 0 || len(r.findings()) != 0 {
					t.Fatalf("a mapping denial after a reload was flagged: %+v", h)
				}
				return
			}
			warn := r.feed(sandboxapi.ReasonHooksUnreachable)
			if !h.Unreachable || h.IngressRefused != 1 || !strings.Contains(h.UnreachableReason, "does not cover the port") ||
				strings.Contains(h.UnreachableReason, "network policy does not allow") || len(warn) != 1 ||
				!strings.HasPrefix(warn[0].Message, "⚠ "+sandboxapi.HooksUnreachableWarning) {
				t.Fatalf("hooks = %+v, feed = %+v", h, warn)
			}
		})
	}
	// A hook through after the reload does not stretch its window.
	r := newReachEnv(t)
	r.line(mapped(testIngressPort))
	r.line(reload)
	r.line(denied)
	r.advance(time.Second)
	r.m.ObserveIngress(r.binding, sandboxauth.RouteHook)
	r.advance(reloadMappingWindow)
	r.line(denied)
	r.advance(hookAttemptGrace + time.Second)
	r.check()
	if h := r.hooks(); !h.Unreachable || h.IngressRefused != 1 {
		t.Fatalf("a mapping denial past the reload after a hook = %+v", h)
	}
}

// The Codex TUI asks its model endpoint for the model list as it opens,
// before any prompt: that start-up call starts no window, so an idle session
// is not flagged (seen live in a MicroVM). A later call without a hook is.
func TestHookReachIgnoresStartupModelCall(t *testing.T) {
	r := newReachEnv(t)
	r.advance(3 * time.Second)
	r.line(modelCall)
	r.advance(time.Minute)
	r.check()
	if h := r.hooks(); h.Unreachable || h.NoHookYet {
		t.Fatalf("an idle session was flagged for its start-up model call: %+v", h)
	}
	r.line(modelCall)
	r.advance(DefaultHookReachWindow + time.Second)
	r.check()
	if h := r.hooks(); !h.Unreachable || !h.NoHookYet {
		t.Fatalf("a model call after start-up without a hook was not flagged: %+v", h)
	}
}

// The layer-7 records on the harness's connection to its model show what
// each request is. The model list, in the start-up grace or after it,
// starts no window; a prompt's model call does at once, also within the
// grace, where the connection alone (no path) would not. Layer-7 records
// name no binary: they are the harness's when the connection they ride on
// is, and a tool's connection to the same endpoint lends them nothing.
func TestHookReachTellsTheModelListFromAModelCall(t *testing.T) {
	const (
		list   = "HTTP:GET [INFO] ALLOWED GET http://api.anthropic.com:443/v1/models?limit=100 [policy:_provider_anthropic engine:l7]"
		prompt = "HTTP:POST [INFO] ALLOWED POST http://api.anthropic.com:443/v1/messages?beta=true [policy:_provider_anthropic engine:l7]"
	)
	idle := func(r *reachEnv) {
		t.Helper()
		for range 6 {
			r.advance(DefaultHookReachWindow)
			r.check()
		}
		if h := r.hooks(); h.Unreachable || h.NoHookYet {
			t.Fatalf("an idle session was flagged: %+v", h)
		}
	}

	// A first prompt within the grace, on the connection the model list
	// opened, starts the window.
	r := newReachEnv(t)
	r.advance(2 * time.Second)
	r.line(modelCall)
	r.line(list)
	r.advance(3 * time.Second)
	r.line(prompt)
	r.advance(DefaultHookReachWindow - time.Second)
	r.check()
	if r.hooks().Unreachable {
		t.Fatalf("flagged within the window: %+v", r.hooks())
	}
	r.advance(2 * time.Second)
	r.check()
	if h := r.hooks(); !h.Unreachable || !h.NoHookYet || !strings.Contains(h.UnreachableReason, "the harness has been calling its model") {
		t.Fatalf("a prompt in the start-up grace without a hook was not flagged: %+v", h)
	}

	// The model list alone, again after the grace, starts none.
	r = newReachEnv(t)
	r.advance(2 * time.Second)
	r.line(modelCall)
	r.line(list)
	r.advance(harnessStartupGrace)
	r.line(list)
	r.line(strings.Replace(list, "/v1/models?limit=100", "/v1/models/claude-sonnet-4-5", 1))
	idle(r)

	// A model call on a tool's connection to the harness's model endpoint
	// is not the harness's, nor is one replayed from before the session.
	r = newReachEnv(t)
	r.line("NET:OPEN [INFO] ALLOWED /usr/bin/curl(3) -> api.anthropic.com:443 [policy:_provider_anthropic engine:opa]")
	r.line(prompt)
	r.ocsf(r.name, prompt, r.m.now().Add(-time.Hour))
	idle(r)
	r = newReachEnv(t)
	r.line(modelCall)
	r.ocsf(r.name, prompt, r.m.now().Add(-time.Hour))
	idle(r)
}

// What the path of a request of the harness to its model shows.
func TestModelRequestOf(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         modelRequest
	}{
		{"", "", modelConnection},
		{"POST", "/v1/messages", modelTurn},
		{"POST", "/v1/messages?beta=true", modelTurn},
		{"POST", "/v1/chat/completions", modelTurn},
		{"POST", "/chat/completions", modelTurn},
		{"POST", "/v1/responses", modelTurn},
		{"POST", "/model/anthropic.claude-sonnet-4-5-v1%3A0/invoke-with-response-stream", modelTurn},
		{"POST", "/model/anthropic.claude-sonnet-4-5-v1%3A0/converse", modelTurn},
		{"POST", "/v1beta/models/gemini-2.5-pro:streamGenerateContent", modelTurn},
		{"GET", "/v1/models", modelListing},
		{"GET", "/v1/models/", modelListing},
		{"GET", "/v1/models/claude-sonnet-4-5", modelListing},
		{"GET", "/foundation-models", modelListing},
		{"GET", "/inference-profiles", modelListing},
		{"GET", "/api/tags", modelListing},
		{"HEAD", "/v1/models", modelListing},
		// A GET of a model call's path opens the Responses API's
		// WebSocket, which a harness may do before any prompt.
		{"GET", "/v1/responses", modelConnection},
		{"POST", "/v1/messages/count_tokens", modelConnection},
		{"POST", "/api/event_logging/batch", modelConnection},
		{"POST", "/v1/models", modelConnection},
	} {
		if got := modelRequestOf(ocsf.Record{Method: tc.method, Path: tc.path}); got != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, got, tc.want)
		}
	}
}

// A harness calling its model without a hook is flagged after the window as
// "no hook yet", not as every tool call blocked; one whose hooks arrived is not.
func TestHookReachSilentWork(t *testing.T) {
	for name, line := range map[string]string{
		"model call":           modelCall,
		"local model endpoint": "NET:OPEN [INFO] ALLOWED " + testClaudeBin + "(9) -> host.openshell.internal:28921 [policy:_provider_dc_cred_1 engine:opa]",
	} {
		t.Run(name, func(t *testing.T) {
			r := newReachEnv(t)
			r.advance(harnessStartupGrace)
			r.line(line)
			r.advance(DefaultHookReachWindow - time.Second)
			r.check()
			if r.hooks().Unreachable {
				t.Fatalf("flagged within the window: %+v", r.hooks())
			}
			r.advance(3 * time.Second)
			r.check()
			if h := r.hooks(); !h.Unreachable || !h.NoHookYet || !strings.Contains(h.UnreachableReason, "the harness has been calling its model for 32s") {
				t.Fatalf("hooks = %+v", h)
			}
			warn := r.feed(sandboxapi.ReasonHooksUnreachable)
			if len(warn) != 1 || !strings.HasPrefix(warn[0].Message, "⚠ No hook has reached DefenseClaw yet (") ||
				strings.Contains(warn[0].Message, sandboxapi.HooksUnreachableWarning) || !strings.HasSuffix(warn[0].Message, sandboxapi.HooksDoctorHint) {
				t.Fatalf("feed = %+v", warn)
			}
			if f := r.findings(); len(f) != 1 || strings.Contains(f[0].Description, "every tool call of the session is blocked") {
				t.Fatalf("findings = %+v", f)
			}
			r.m.ObserveIngress(r.binding, sandboxauth.RouteHook)
			if r.hooks().Unreachable || r.hooks().NoHookYet {
				t.Fatalf("after a hook = %+v", r.hooks())
			}
		})
	}
	r := newReachEnv(t)
	r.m.ObserveIngress(r.binding, sandboxauth.RouteHook)
	r.line("HTTP:POST [INFO] ALLOWED POST https://api.anthropic.com/v1/messages [policy:anthropic engine:l7]")
	r.advance(time.Hour)
	r.check()
	if r.hooks().Unreachable {
		t.Fatalf("a session with hooks was flagged: %+v", r.hooks())
	}
}

// No model call, nothing flagged: the proxy's relay, a tool's process,
// replayed records, and a harness's start-up traffic through the proxy and
// around it (which live raised the alarm on first-run screens).
func TestHookReachQuietCases(t *testing.T) {
	r := newReachEnv(t)
	r.line("NET:OPEN [INFO] ALLOWED /usr/bin/curl(3) -> host.openshell.internal:" + strconv.Itoa(testEgressPort) + " [policy:defenseclaw_egress engine:opa]")
	r.line("PROC:LAUNCH [INFO] git(42) [cmd:git status]")
	r.ocsf(r.name, ingressLine("DENIED"), r.m.now().Add(-time.Hour))
	for _, host := range []string{"pypi.org", "antigravity-unleash.goog", "raw.githubusercontent.com"} {
		r.m.egressEvent(t.Context(), egress.Event{Kind: egress.EventAllowed, SandboxName: r.name, Host: host, Port: 443, Time: r.m.now(), FirstSeen: true}, 0)
		r.m.egressEvent(t.Context(), egress.Event{Kind: egress.EventClosed, SandboxName: r.name, Host: host, Port: 443, Time: r.m.now()}, 0)
	}
	r.line("NET:OPEN [MED] DENIED " + testClaudeBin + "(9) -> play.googleapis.com:443 [reason:transparent_tcp_policy_denied]")
	r.line("NET:OPEN [INFO] ALLOWED " + testClaudeBin + "(9) -> registry.example.org:443 [policy:allow_registry_example_org_443 engine:opa]")
	r.line("NET:OPEN [INFO] ALLOWED /usr/bin/curl(3) -> api.anthropic.com:443 [policy:_provider_anthropic engine:opa]")
	for range 4 {
		r.advance(DefaultHookReachWindow)
		r.check()
	}
	if h := r.hooks(); h.Unreachable || h.IngressRefused != 1 || len(r.feed(sandboxapi.ReasonHooksUnreachable)) != 0 || len(r.findings()) != 0 {
		t.Fatalf("an idle sandbox was flagged: %+v", h)
	}
}

// An idle Codex TUI's authenticated OTLP (its hooks fire with the first
// prompt) is no sign of work; the first model call without hooks is.
func TestHookReachIdleTelemetry(t *testing.T) {
	r := newReachEnv(t)
	r.line("NET:OPEN [INFO] ALLOWED /opt/defenseclaw-harness/codex/bin/codex(81) -> host.openshell.internal:" + strconv.Itoa(testIngressPort) +
		" [policy:defenseclaw_ingress engine:opa]")
	r.m.ObserveIngress(r.binding, sandboxauth.RouteOTLP)
	for range 6 {
		r.advance(DefaultHookReachWindow)
		r.m.ObserveIngress(r.binding, sandboxauth.RouteOTLP)
		r.check()
	}
	if r.hooks().Unreachable {
		t.Fatalf("an idle harness exporting telemetry was flagged: %+v", r.hooks())
	}
	r.line("NET:OPEN [INFO] ALLOWED " + testClaudeBin + "(81) -> bedrock-mantle.us-east-1.api.aws:443 [policy:_provider_x engine:opa]")
	r.advance(DefaultHookReachWindow + time.Second)
	r.check()
	if !r.hooks().Unreachable || !strings.Contains(r.hooks().UnreachableReason, "the harness has been calling its model") {
		t.Fatalf("a model call without hooks = %+v", r.hooks())
	}
}

// A new session (the sandbox ready again) starts over: the flag clears and
// its first problem is warned about again.
func TestHookReachNewSessionStartsOver(t *testing.T) {
	r := newReachEnv(t)
	r.line(ingressLine("DENIED"))
	if !r.hooks().Unreachable {
		t.Fatal("not flagged")
	}
	b := r.boxOf(r.name)
	r.m.lifecycle(t.Context(), b, audit.SandboxPhaseStopped, audit.SandboxTriggerStop, false, nil, nil)
	r.advance(time.Minute)
	r.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerStart, false, nil, nil)
	if h := r.hooks(); h.Unreachable || h.IngressRefused != 1 {
		t.Fatalf("hooks of the new session = %+v", h)
	}
	r.advance(time.Second)
	r.line(ingressLine("DENIED"))
	if len(r.feed(sandboxapi.ReasonHooksUnreachable)) != 2 {
		t.Fatalf("warnings = %d, want one per session", len(r.feed(sandboxapi.ReasonHooksUnreachable)))
	}
}
