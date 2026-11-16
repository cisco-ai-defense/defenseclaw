// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// copilotLiveGateHook is one Copilot CLI hook body run in __CWD__.
func copilotLiveGateHook(event, body string) requireSandboxHook {
	return requireSandboxHook{connector: "copilot", path: "/api/v1/copilot/hook", body: body,
		headers: map[string]string{"X-DefenseClaw-Copilot-Event": event}}
}

func copilotLiveGateAction(t *testing.T, out map[string]any) (string, string) {
	t.Helper()
	text, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	action, _ := out["action"].(string)
	return action, string(text)
}

// An unreadable Copilot call in observe mode is allowed with a warning
// without evaluation; that allow must not skip the require-sandbox gate a
// floor requiring Copilot in a sandbox applies to every host run (P1
// regression, loop round 2 of review e).
func TestCopilotUnparsedObserveAllowRunsTheSandboxGate(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	for _, hook := range []struct {
		name string
		hook requireSandboxHook
	}{
		{"unbound argumentless permission callback", copilotLiveGateHook("permissionRequest",
			`{"hookName":"permissionRequest","sessionId":"unbound","cwd":"__CWD__","toolName":"edit","toolInput":{}}`)},
		{"native tool call with an unknown field", copilotLiveGateHook("preToolUse",
			`{"sessionId":"multi","cwd":"__CWD__","toolCalls":[{"id":"a","name":"bash","args":{"command":"ls"}},{"id":"b","name":"bash","args":{"command":"pwd"},"extra":true}]}`)},
		{"decoy dialect field", copilotLiveGateHook("preToolUse",
			`{"sessionId":"decoy","cwd":"__CWD__","toolName":"bash","toolArgs":"{\"command\":\"ls\"}","tool_name":"bash"}`)},
	} {
		t.Run(hook.name, func(t *testing.T) {
			project := requireSandboxProject(t)
			// Control: with no floor the call takes the observe allow
			// for an unreadable call (so the refusal below is the gate).
			api, _ := requireSandboxTestAPI(t, "")
			action, text := copilotLiveGateAction(t, postRequireSandboxHook(t, api, hook.hook, project, nil, nil))
			if action != "allow" || !strings.Contains(text, hookToolCallUnparsedRuleID) {
				t.Fatalf("control: want the observe allow of an unreadable call, got %s", text)
			}
			api, store := requireSandboxTestAPI(t, "", "copilot")
			action, text = copilotLiveGateAction(t, postRequireSandboxHook(t, api, hook.hook, project, nil, nil))
			if action == "allow" || !strings.Contains(strings.ToLower(text), "sandbox") {
				t.Fatalf("unreadable observe call skipped the required sandbox gate: %s", text)
			}
			if got := requireSandboxAuditOutcome(t, store); got != requireSandboxRefused {
				t.Fatalf("audit require_sandbox = %q, want %q", got, requireSandboxRefused)
			}
		})
	}
}

// A second delivery of one Copilot call reuses the first delivery's allow
// only while the live gates still pass: a floor that starts to require
// Copilot in a sandbox between the deliveries refuses the second one. A
// native toolCalls delivery never answers another delivery (P2 regression,
// loop round 2 of review e).
func TestCopilotDedupeReplaysAnAllowOnlyUnderTheLiveGates(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	native := func(session, project string) string {
		return `{"sessionId":"` + session + `","cwd":` + copilotJoinQuote(t, project) +
			`,"toolCalls":[{"id":"call_1","name":"bash","args":{"command":"ls"}}]}`
	}
	camel := func(session, project string) string {
		return `{"sessionId":"` + session + `","cwd":` + copilotJoinQuote(t, project) +
			`,"toolName":"bash","toolArgs":"{\"command\":\"ls\"}"}`
	}
	for _, tc := range []struct {
		name          string
		first, second func(string, string) string
	}{
		{"native then camelCase", native, camel},
		{"camelCase then native", camel, native},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := requireSandboxProject(t)
			f := newManagedHookAuditFixtureFor(t, "copilot", nil)
			cfg := f.api.liveBaseConfig(t.Context())
			cfg.OpenShell.Enabled = true
			cfg.OpenShell.Admin.RequestAccess = "it-security@example.com"
			if line := copilotJoinManagedPost(t, f, "preToolUse", tc.first("floor", project)); !strings.Contains(line, `"action":"allow"`) {
				t.Fatalf("first delivery: %s", line)
			}
			cfg.OpenShell.Admin.RequiredFor = []string{"copilot"}
			line := copilotJoinManagedPost(t, f, "preToolUse", tc.second("floor", project))
			if strings.Contains(line, `"action":"allow"`) || !strings.Contains(strings.ToLower(line), "sandbox") {
				t.Fatalf("second delivery replayed an allow past the newly required sandbox gate: %s", line)
			}
			if got := requireSandboxAuditOutcome(t, f.store); got != requireSandboxRefused && got != requireSandboxUnavailable {
				t.Fatalf("audit require_sandbox = %q, want a refusal: %s", got, line)
			}
		})
	}
}

// The keys carry the policy the verdict was decided under, and a native
// toolCalls delivery or an unreadable call takes none.
func TestCopilotDedupeKeysCarryThePolicy(t *testing.T) {
	ctx := context.Background()
	camel := agentHookRequest{HookEventName: "preToolUse", SessionID: "s1", CWD: "/project", ToolName: "bash",
		ToolArgs: json.RawMessage(`"{\"command\":\"ls\"}"`), Payload: map[string]any{"toolName": "bash", "toolArgs": `{"command":"ls"}`}}
	snake := agentHookRequest{HookEventName: "PreToolUse", SessionID: "s1", CWD: "/project", ToolName: "bash",
		ToolArgs: json.RawMessage(`{"command":"ls"}`), Payload: map[string]any{"tool_name": "bash", "tool_input": map[string]any{"command": "ls"}}}
	allow := agentHookResponse{Action: "allow", EvaluationID: "allowed"}

	var d copilotHookDedupe
	_, _, first := d.begin(ctx, "copilot", camel, "gen-1")
	first.complete(allow)
	if _, hit, _ := d.begin(ctx, "copilot", snake, "gen-2"); hit {
		t.Fatal("a verdict of another policy answered the second delivery")
	}
	if got, hit, _ := d.begin(ctx, "copilot", snake, "gen-1"); !hit || got.EvaluationID != "allowed" {
		t.Fatalf("same policy did not deduplicate: hit=%v", hit)
	}

	native := camel
	native.Payload = map[string]any{"toolCalls": []any{map[string]any{"id": "c", "name": "bash", "args": map[string]any{"command": "ls"}}}}
	unread := snake
	unread.ToolCallUnparsed = true
	for name, req := range map[string]agentHookRequest{"native toolCalls": native, "unparsed": unread} {
		if exact, content, _, _ := copilotDedupeKeys(ctx, "copilot", req, "gen-1"); exact != "" || content != "" {
			t.Fatalf("%s delivery took dedupe keys", name)
		}
	}
}

// copilotDedupeReplayable lets an earlier block answer a delivery always, an
// earlier allow only while the live require-sandbox floor (or a refused
// profile) does not refuse this host run now. This holds for the paired CLI
// dialects too, whose second delivery is never evaluated on its own.
func TestCopilotDedupeReplayableReadsTheLiveGates(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	ctx := withManagedHookPeer(t.Context(), managedHookPeer{UID: 1001, Name: "alice"})
	req := agentHookRequest{ConnectorName: "copilot", HookEventName: "preToolUse", SessionID: "s1",
		CWD: requireSandboxProject(t), ToolName: "bash", ToolArgs: json.RawMessage(`{"command":"ls"}`)}
	allow := agentHookResponse{Action: "allow"}
	block := agentHookResponse{Action: "block"}
	api, _ := requireSandboxTestAPI(t, "")
	if !api.copilotDedupeReplayable(ctx, "copilot", req, "", allow) {
		t.Fatal("an allow was not replayable with no floor")
	}
	api.liveBaseConfig(ctx).OpenShell.Admin.RequiredFor = []string{"copilot"}
	if api.copilotDedupeReplayable(ctx, "copilot", req, "", allow) {
		t.Fatal("an allow was replayable past a floor that requires Copilot in a sandbox")
	}
	if !api.copilotDedupeReplayable(ctx, "copilot", req, "", block) {
		t.Fatal("a block was not replayable")
	}
}
