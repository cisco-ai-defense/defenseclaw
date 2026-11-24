// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func copilotShellJQOrSkip(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		if _, err := os.Stat("/usr/local/bin/jq"); err != nil {
			t.Skip("jq is required to run the Copilot shell hook")
		}
	}
}

// gap2130Verdicts are gateway answers that block or confirm a Copilot tool
// boundary without the native deny or ask the verdict needs.
var gap2130Verdicts = map[string]map[string]interface{}{
	"block, empty output":        {"action": "block", "raw_action": "block", "hook_output": map[string]string{}},
	"block, no output":           {"action": "block", "raw_action": "block"},
	"block, allow-shaped output": {"action": "block", "raw_action": "block", "hook_output": map[string]string{"permissionDecision": "allow", "behavior": "allow"}},
	"confirm, empty output":      {"action": "confirm", "raw_action": "confirm", "hook_output": map[string]string{}},
}

var gap2130Denies = map[string]string{"preToolUse": `"permissionDecision":"deny"`, "permissionRequest": `"behavior":"deny"`}

const gap2130Payload = `{"cwd":"/tmp","toolName":"bash","toolArgs":"{\"command\":\"echo marker\"}"}`

// GAP-2130: on every Copilot shell render that is not Secure Client
// (per-user, standalone managed, sandbox), a gateway block or confirmation of
// a tool call or permission request without Copilot's native deny or ask is
// refused, in both installed fail modes: the gateway answered, so it is no
// outage, as the native hook (failNativeDecision) refuses it. Before the fix
// the sandbox hook forwarded an allow-shaped or empty output with exit 0, so
// the call ran. The per-user and standalone renders already refused it (a
// per-user script bakes closed for every non-outage failure); they are pinned
// here.
func TestGAP2130CopilotShellHooksRefuseAVerdictWithoutItsNativeAnswer(t *testing.T) {
	copilotShellJQOrSkip(t)
	for event, deny := range gap2130Denies {
		args := []string{"--event", event}
		for name, verdict := range gap2130Verdicts {
			reply := "200|" + string(mustMarshalForGAP2130(t, verdict))
			for _, mode := range []string{"open", "closed"} {
				run := runPerUserHookForStop(t, NewCopilotConnector(), "copilot-hook.sh", args, gap2130Payload, reply, "DEFENSECLAW_FAIL_MODE="+mode)
				if run.code != 0 || !strings.Contains(run.stdout, deny) {
					t.Errorf("per-user %s %s %s: %+v, want exit 0 and %s", mode, event, name, run, deny)
				}
				f := newHookSocketFixture(t, "dc2130", verdict)
				code, stdout, stderr := runStandaloneShellHookInMode(t, f, NewCopilotConnector(), "copilot-hook.sh", args, gap2130Payload, mode)
				if code != 0 || !strings.Contains(stdout, deny) {
					t.Errorf("standalone managed %s %s %s: exit %d stdout=%q stderr=%q, want exit 0 and %s", mode, event, name, code, stdout, stderr, deny)
				}
			}
			h := newSandboxHookHarness(t, NewCopilotConnector(), "1.0.88")
			run := h.run(t, SandboxHookDir+"/copilot-hook.sh", args, gap2130Payload, map[string]string{SandboxTokenEnv: "tok"}, []string{reply})
			if run.exitCode != 2 || strings.Contains(run.stdout, "allow") {
				t.Errorf("sandbox %s %s: exit %d stdout=%q stderr=%q, want exit 2 (Copilot's hook deny) and no allow",
					event, name, run.exitCode, run.stdout, run.stderr)
			}
		}
	}
	// An allowed call and a block that carries its deny are unchanged.
	allowed := `200|{"action":"allow","raw_action":"allow","hook_output":{}}`
	blocked := `200|{"action":"block","raw_action":"block","hook_output":{"permissionDecision":"deny","permissionDecisionReason":"nope"}}`
	for _, mode := range []string{"open", "closed"} {
		if run := runPerUserHookForStop(t, NewCopilotConnector(), "copilot-hook.sh", []string{"--event", "preToolUse"}, gap2130Payload, allowed,
			"DEFENSECLAW_FAIL_MODE="+mode); run.code != 0 || strings.Contains(run.stdout, "deny") {
			t.Errorf("per-user %s allowed call: %+v, want no deny", mode, run)
		}
		if run := runPerUserHookForStop(t, NewCopilotConnector(), "copilot-hook.sh", []string{"--event", "preToolUse"}, gap2130Payload, blocked,
			"DEFENSECLAW_FAIL_MODE="+mode); run.code != 0 || !strings.Contains(run.stdout, `"permissionDecisionReason":"nope"`) {
			t.Errorf("per-user %s block with its deny: %+v, want the gateway's deny", mode, run)
		}
	}
	h := newSandboxHookHarness(t, NewCopilotConnector(), "1.0.88")
	if run := h.run(t, SandboxHookDir+"/copilot-hook.sh", []string{"--event", "preToolUse"}, gap2130Payload,
		map[string]string{SandboxTokenEnv: "tok"}, []string{allowed}); run.exitCode != 0 || strings.Contains(run.stdout, "deny") {
		t.Errorf("sandbox allowed call: exit %d stdout=%q stderr=%q, want exit 0 and no deny", run.exitCode, run.stdout, run.stderr)
	}
}

// gap2131Prompt is the prefix of every replacement of a Copilot CLI prompt.
const gap2131Prompt = `{"modifiedTransformedPrompt":"DefenseClaw blocked the current user message. Do not answer it or call tools for it. Reply only: `

// GAP-2131: a Copilot CLI prompt whose check fails closed is replaced with
// DefenseClaw's notice, on the shell hooks: per-user with the gateway down in
// fail mode closed (open lets it through, the OSS default), standalone
// managed with the gateway stopped and on an unusable answer, and the sandbox
// on an ingress failure and an unusable answer. Claude Code, Codex, Cursor
// and Kiro block a prompt in the same cases. Before the fix the hook printed
// nothing for the event and the prompt reached the model.
func TestGAP2131CopilotShellHooksReplaceAPromptWhoseCheckFailsClosed(t *testing.T) {
	copilotShellJQOrSkip(t)
	args := []string{"--event", "userPromptTransformed"}
	const payload = `{"cwd":"/tmp","prompt":"hi","transformedPrompt":"hi"}`
	// Per-user: the outage mode is the runtime config's (none here: closed),
	// so the prompt is replaced exactly when a tool call is denied, whatever
	// mode the script was rendered with.
	for _, mode := range []string{"open", "closed"} {
		run := runPerUserHookForStop(t, NewCopilotConnector(), "copilot-hook.sh", args, payload, "exit:", "DEFENSECLAW_FAIL_MODE="+mode)
		tool := runPerUserHookForStop(t, NewCopilotConnector(), "copilot-hook.sh", []string{"--event", "preToolUse"}, gap2130Payload, "exit:",
			"DEFENSECLAW_FAIL_MODE="+mode)
		denied := strings.Contains(tool.stdout, `"permissionDecision":"deny"`)
		replaced := strings.HasPrefix(strings.TrimSpace(run.stdout), gap2131Prompt) && strings.Contains(run.stdout, "DefenseClaw blocked this prompt")
		if run.code != 0 || !denied || replaced != denied {
			t.Errorf("per-user %s, gateway down: prompt %+v, tool denied=%t; want both closed", mode, run, denied)
		}
	}
	for _, mode := range []string{"open", "closed"} {
		f := newHookSocketFixture(t, "dc2131", map[string]interface{}{"action": "maybe"})
		code, stdout, stderr := runStandaloneShellHookInMode(t, f, NewCopilotConnector(), "copilot-hook.sh", args, payload, mode)
		if code != 0 || !strings.HasPrefix(strings.TrimSpace(stdout), gap2131Prompt) {
			t.Errorf("standalone managed %s, unusable answer: exit %d stdout=%q stderr=%q, want the prompt replaced", mode, code, stdout, stderr)
		}
		if err := os.Remove(f.socket); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr = runStandaloneShellHookInMode(t, f, NewCopilotConnector(), "copilot-hook.sh", args, payload, mode)
		if code != 0 || !strings.HasPrefix(strings.TrimSpace(stdout), gap2131Prompt) {
			t.Errorf("standalone managed %s, gateway stopped: exit %d stdout=%q stderr=%q, want the prompt replaced", mode, code, stdout, stderr)
		}
	}
	for name, replies := range map[string][]string{"ingress down": {"exit:7", "exit:7"}, "unusable answer": {`200|{"action":"maybe"}`}} {
		h := newSandboxHookHarness(t, NewCopilotConnector(), "1.0.88")
		run := h.run(t, SandboxHookDir+"/copilot-hook.sh", args, payload, map[string]string{SandboxTokenEnv: "tok"}, replies)
		if run.exitCode != 0 || !strings.HasPrefix(strings.TrimSpace(run.stdout), gap2131Prompt) {
			t.Errorf("sandbox %s: exit %d stdout=%q stderr=%q, want the prompt replaced", name, run.exitCode, run.stdout, run.stderr)
		}
	}
	// An allowed prompt is not modified on any render.
	allowed := map[string]interface{}{"action": "allow", "raw_action": "allow", "hook_output": map[string]string{}}
	if run := runPerUserHookForStop(t, NewCopilotConnector(), "copilot-hook.sh", args, payload, `200|{"action":"allow","raw_action":"allow","hook_output":{}}`,
		"DEFENSECLAW_FAIL_MODE=closed"); run.code != 0 || strings.Contains(run.stdout, "modifiedTransformedPrompt") {
		t.Errorf("per-user allowed prompt: %+v, want no replacement", run)
	}
	f := newHookSocketFixture(t, "dc2131a", allowed)
	if code, stdout, stderr := runStandaloneShellHookInMode(t, f, NewCopilotConnector(), "copilot-hook.sh", args, payload, "closed"); code != 0 ||
		strings.Contains(stdout, "modifiedTransformedPrompt") {
		t.Errorf("standalone allowed prompt: exit %d stdout=%q stderr=%q, want no replacement", code, stdout, stderr)
	}
}

func mustMarshalForGAP2130(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
