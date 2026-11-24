// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// vaultHarnessCase is one sandbox hook call of a harness that carries a
// made-up key: in the prompt, in a tool call's input, in a tool's output
// or in the agent's reply.
type vaultHarnessCase struct {
	name    string
	spec    *harness.Spec
	path    string
	event   string
	headers []string
	body    func(key string) string
	// anthropic: the body carries the Anthropic-shaped key (a prompt),
	// otherwise the Stripe-shaped one (a tool call or its output).
	anthropic bool
	// stop: the call is answered block; otherwise alert (the event cannot
	// stop anything, or stopping it would restart the agent's turn).
	stop bool
	// exposed: the model has seen (or wrote) the value.
	exposed bool
	// held: the event stores nothing new (a reply); the vault holds the
	// value before the call, and the call marks it exposed.
	held bool
}

func vaultHarnessCases() []vaultHarnessCase {
	copilotEvent := func(e string) []string { return []string{"X-DefenseClaw-Copilot-Event", e} }
	const copilotSession = `"sessionId":"506e99d3-3a4f-4a7c-9d0e-0f2c6d1e8b11","timestamp":1790483549431,"cwd":"/work/app"`
	const kiroSession = `"cwd":"/work/app","session_id":"c2197843-ce66-4011-a627-052241fa9da8"`
	const openCodeCall = `"session_id":"ses_vc","turn_id":"msg_vc","tool_call_id":"call_vc","cwd":"/work/app",` +
		`"load_heartbeat":true,"arguments_authoritative":true,"mcp_identity_status":"not_mcp"`
	const cursorTurn = `"conversation_id":"conv-vc","generation_id":"gen-vc","cwd":"/work/app"`
	const devinTurn = `"session_id":"amber-otter","prompt_id":"3f6c2a91-5d7e-4b08-9c1a-2e8f0d4b7a63"`
	return []vaultHarnessCase{
		// Claude Code: a value the model assembles at run time reaches the
		// hook only in the tool's output.
		{name: "claudecode-PostToolUse", spec: harness.ClaudeCode, path: "/api/v1/claude-code/hook", event: "PostToolUse", stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"PostToolUse","session_id":"s-vc","cwd":"/work/app","tool_name":"Bash","tool_input":{"command":"sh gen.sh"},` +
					`"tool_response":{"stdout":"STRIPE_KEY=` + k + `\n","stderr":"","interrupted":false,"isImage":false},"tool_use_id":"toolu_vc"}`
			}},
		{name: "claudecode-Stop", spec: harness.ClaudeCode, path: "/api/v1/claude-code/hook", event: "Stop", exposed: true, held: true,
			body: func(k string) string {
				return `{"hook_event_name":"Stop","session_id":"s-vc","cwd":"/work/app","stop_hook_active":false,"last_assistant_message":"Wrote STRIPE_KEY=` + k + ` to local.env"}`
			}},
		{name: "codex-PostToolUse", spec: harness.Codex, path: "/api/v1/codex/hook", event: "PostToolUse", stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"PostToolUse","session_id":"s-vc","turn_id":"t1","cwd":"/work/app","tool_name":"Bash",` +
					`"tool_input":{"command":"sh gen.sh"},"tool_response":"STRIPE_KEY=` + k + `\n","tool_use_id":"u-vc"}`
			}},
		// Copilot CLI cannot stop a prompt: the model reads it.
		{name: "copilot-userPromptSubmitted", spec: harness.Copilot, path: "/api/v1/copilot/hook", event: "userPromptSubmitted", anthropic: true, stop: true, exposed: true,
			headers: copilotEvent("userPromptSubmitted"),
			body:    func(k string) string { return `{` + copilotSession + `,"prompt":"call the API with ` + k + ` please"}` }},
		{name: "copilot-preToolUse", spec: harness.Copilot, path: "/api/v1/copilot/hook", event: "preToolUse", stop: true, exposed: true,
			headers: copilotEvent("preToolUse"),
			body: func(k string) string {
				return `{` + copilotSession + `,"toolName":"bash","toolArgs":{"command":"printf 'STRIPE_KEY=` + k + `\\n' > local.env","description":"write env"}}`
			}},
		{name: "copilot-postToolUse", spec: harness.Copilot, path: "/api/v1/copilot/hook", event: "postToolUse", exposed: true,
			headers: copilotEvent("postToolUse"),
			body: func(k string) string {
				return `{` + copilotSession + `,"toolName":"bash","toolArgs":{"command":"sh gen.sh","description":"generate"},` +
					`"toolResult":{"resultType":"success","textResultForLlm":"STRIPE_KEY=` + k + `\n"}}`
			}},
		// OpenCode has no prompt hook.
		{name: "opencode-tool.execute.before", spec: harness.OpenCode, path: "/api/v1/opencode/hook", event: "tool.execute.before", stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"tool.execute.before","tool_name":"bash","tool_input":{"command":"printf 'STRIPE_KEY=` + k + `\\n' > local.env"},` + openCodeCall + `}`
			}},
		{name: "opencode-tool.execute.after", spec: harness.OpenCode, path: "/api/v1/opencode/hook", event: "tool.execute.after", exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"tool.execute.after","tool_name":"bash","tool_input":{"command":"sh gen.sh"},` + openCodeCall +
					`,"tool_response":{"title":"sh","output":"STRIPE_KEY=` + k + `\n","metadata":{"exit":0}}}`
			}},
		// Hermes cannot stop a prompt: the agent is told not to carry it out.
		{name: "hermes-pre_llm_call", spec: harness.Hermes, path: "/api/v1/hermes/hook", event: "pre_llm_call", anthropic: true, stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"pre_llm_call","session_id":"20260927_1","cwd":"/work/app","extra":{"user_message":"call the API with ` + k + ` please"}}`
			}},
		{name: "hermes-pre_tool_call", spec: harness.Hermes, path: "/api/v1/hermes/hook", event: "pre_tool_call", stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"printf 'STRIPE_KEY=` + k + `\\n' > local.env"},` +
					`"session_id":"20260927_1","cwd":"/work/app","extra":{"tool_call_id":"call_1","task_id":"t1"}}`
			}},
		{name: "hermes-post_tool_call", spec: harness.Hermes, path: "/api/v1/hermes/hook", event: "post_tool_call", exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"post_tool_call","tool_name":"terminal","tool_input":{"command":"sh gen.sh"},` +
					`"session_id":"20260927_1","cwd":"/work/app","extra":{"tool_call_id":"call_1","task_id":"t1","result":"STRIPE_KEY=` + k + `"}}`
			}},
		// Kiro CLI 2.x does not apply a userPromptSubmit veto.
		{name: "kiro-userPromptSubmit", spec: harness.Kiro, path: "/api/v1/kiro/hook", event: "userPromptSubmit", anthropic: true, stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"userPromptSubmit",` + kiroSession + `,"prompt":"call the API with ` + k + ` please"}`
			}},
		{name: "kiro-preToolUse", spec: harness.Kiro, path: "/api/v1/kiro/hook", event: "preToolUse", stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"preToolUse",` + kiroSession + `,"tool_name":"shell","tool_input":{"command":"printf 'STRIPE_KEY=` + k + `\\n' > local.env"}}`
			}},
		{name: "kiro-postToolUse", spec: harness.Kiro, path: "/api/v1/kiro/hook", event: "postToolUse", exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"postToolUse",` + kiroSession + `,"tool_name":"shell","tool_input":{"command":"sh gen.sh"},` +
					`"tool_response":{"items":[{"Text":"STRIPE_KEY=` + k + `\n"}]}}`
			}},
		// Antigravity's PreInvocation and PostToolUse carry no prompt and no
		// tool output: only the tool call reaches the gateway.
		{name: "antigravity-PreToolUse", spec: harness.Antigravity, path: "/api/v1/antigravity/hook", event: "PreToolUse", stop: true, exposed: true,
			headers: []string{"X-DefenseClaw-Antigravity-Event", "PreToolUse"},
			body: func(k string) string {
				return `{"conversationId":"c1","workspacePaths":["/work/app"],"stepIdx":3,"toolCall":{"name":"run_command","args":{` +
					`"CommandLine":"printf 'STRIPE_KEY=` + k + `\\n' > local.env","Cwd":"/work/app","WaitMsBeforeAsync":500,"toolSummary":"write env","toolAction":"Writing env"}}}`
			}},
		// Amp's agent.start carries the prompt; its plugin can only add a
		// note for the model there.
		{name: "amp-agent.start", spec: harness.Amp, path: "/api/v1/amp/hook", event: "agent.start", anthropic: true, stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"agent.start","thread_id":"T-vc","session_id":"T-vc","turn_id":"t1","message_id":"t1",` +
					`"prompt":"call the API with ` + k + ` please","cwd":"/work/app"}`
			}},
		{name: "amp-tool.call", spec: harness.Amp, path: "/api/v1/amp/hook", event: "tool.call", stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"tool.call","thread_id":"T-vc","session_id":"T-vc","tool_call_id":"toolu_amp_vc",` +
					`"tool_name":"Bash","tool_input":{"cmd":"printf 'STRIPE_KEY=` + k + `\\n' > local.env"},"cwd":"/work/app"}`
			}},
		{name: "amp-tool.result", spec: harness.Amp, path: "/api/v1/amp/hook", event: "tool.result", stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"tool.result","thread_id":"T-vc","session_id":"T-vc","tool_call_id":"toolu_amp_vc",` +
					`"tool_name":"Bash","tool_input":{"cmd":"sh gen.sh"},"tool_response":{"output":"STRIPE_KEY=` + k + `\n"},"status":"done","error":"","cwd":"/work/app"}`
			}},
		{name: "cursor-beforeSubmitPrompt", spec: harness.Cursor, path: "/api/v1/cursor/hook", event: "beforeSubmitPrompt", anthropic: true, stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"beforeSubmitPrompt",` + cursorTurn + `,"prompt":"call the API with ` + k + ` please"}`
			}},
		{name: "cursor-preToolUse", spec: harness.Cursor, path: "/api/v1/cursor/hook", event: "preToolUse", stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"preToolUse",` + cursorTurn + `,"tool_name":"Shell","tool_input":{"command":"printf 'STRIPE_KEY=` + k + `\\n' > local.env"},"tool_use_id":"tool_cursor_vc"}`
			}},
		{name: "cursor-postToolUse", spec: harness.Cursor, path: "/api/v1/cursor/hook", event: "postToolUse", exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"postToolUse",` + cursorTurn + `,"tool_name":"Shell","tool_input":{"command":"sh gen.sh"},` +
					`"tool_output":"STRIPE_KEY=` + k + `\n","tool_use_id":"tool_cursor_vc"}`
			}},
		{name: "devin-UserPromptSubmit", spec: harness.Devin, path: "/api/v1/devin/hook", event: "UserPromptSubmit", anthropic: true, stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"UserPromptSubmit",` + devinTurn + `,"prompt":"call the API with ` + k + ` please"}`
			}},
		{name: "devin-PreToolUse", spec: harness.Devin, path: "/api/v1/devin/hook", event: "PreToolUse", stop: true, exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"PreToolUse",` + devinTurn + `,"tool_name":"exec","tool_input":{"command":"printf 'STRIPE_KEY=` + k + `\\n' > local.env"},"tool_use_id":"tu_vc"}`
			}},
		{name: "devin-PostToolUse", spec: harness.Devin, path: "/api/v1/devin/hook", event: "PostToolUse", exposed: true,
			body: func(k string) string {
				return `{"hook_event_name":"PostToolUse",` + devinTurn + `,"tool_name":"exec","tool_input":{"command":"sh gen.sh"},"tool_use_id":"tu_vc",` +
					`"tool_response":{"success":true,"output":"STRIPE_KEY=` + k + `\n","error":null}}`
			}},
	}
}

// Every sandboxed harness's hook events that carry a secret capture it:
// the value goes into the vault, out of the hook body and out of the
// answer. A prompt the harness cannot stop, a tool call and a tool's
// output are stored exposed (the model has seen the value); the call is
// answered with the strongest answer the event allows.
func TestSandboxVaultCaptureCoversEveryHarness(t *testing.T) {
	for _, tc := range vaultHarnessCases() {
		t.Run(tc.name, func(t *testing.T) {
			st := vault.Open(filepath.Join(t.TempDir(), "vault"))
			f := newSandboxIngressFixture(t, withTestVault(st))
			version := tc.spec.DefaultVersion
			contract := connector.ResolveSandboxHookContract(tc.spec.Name, version)
			if contract.Status != connector.HookCompatibilityKnown {
				t.Fatalf("%s %s: no sandbox hook contract: %s", tc.spec.Name, version, contract.Reason)
			}
			_, token := f.mint(t, "dc-vc-"+tc.spec.Name, tc.spec.Name, version, contract.Contract.ContractID, "")
			key, name := vaultTestStripeKey(), "STRIPE_API_KEY"
			if tc.anthropic {
				key, name = vaultTestAnthropicKey(), "ANTHROPIC_API_KEY"
			}
			if tc.held {
				if _, err := st.Add(vault.AddInput{Name: name, Value: key, Host: "api.example.com"}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.spec.Name == "codex" {
				// Codex hooks name the event and contract they are bound to.
				tc.headers = []string{"X-DefenseClaw-Hook-Event", tc.event, "X-DefenseClaw-Hook-Contract", contract.Contract.ContractID}
			}
			rec := f.do(t, http.MethodPost, tc.path, token, tc.body(key), tc.headers...)
			if rec.Code != http.StatusOK {
				t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), key) {
				t.Fatal("the answer carries the secret")
			}
			e, err := st.Get(name)
			if err != nil {
				t.Fatalf("no vault entry %s after a %s call that carried it: %v", name, tc.event, err)
			}
			if e.Exposed != tc.exposed || (!tc.held && (!strings.Contains(e.CapturedFrom, tc.event) || !strings.Contains(e.CapturedFrom, "dc-vc-"+tc.spec.Name))) {
				t.Fatalf("entry = %+v", e)
			}
			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			want := "alert"
			if tc.stop {
				want = "block"
			}
			reason, _ := resp["reason"].(string)
			if resp["action"] != want || !strings.Contains(reason, name) {
				t.Fatalf("answer = %v (want action %s naming %s)", resp, want, name)
			}
			if tc.exposed && !strings.Contains(reason, "vault replace "+name) {
				t.Fatalf("the answer does not tell the user to rotate and replace %s: %q", name, reason)
			}
			if tc.spec.Name == "claudecode" && !tc.stop {
				// A Stop answered block would restart the agent's turn.
				if out, _ := resp["claude_code_output"].(map[string]interface{}); out["decision"] == "block" {
					t.Fatalf("a non-stopping event was answered decision block: %v", out)
				}
			}
			// The same value seen again keeps one entry.
			if rec := f.do(t, http.MethodPost, tc.path, token, tc.body(key), tc.headers...); rec.Code != http.StatusOK {
				t.Fatalf("second hook: %d %s", rec.Code, rec.Body.String())
			}
			list, err := st.List()
			if err != nil || len(list) != 1 {
				t.Fatalf("entries after the same value twice = %+v (%v)", list, err)
			}
		})
	}
}
