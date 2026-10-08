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

package gateway

import (
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// fakeRefusals is the manager's refusal lookup for the ingress fixture:
// what was added for a binding is handed out once, to that binding.
type fakeRefusals struct {
	mu      sync.Mutex
	pending map[string][]SandboxEgressRefusal
	asked   []string
}

func (r *fakeRefusals) add(b sandboxauth.Binding, refusals ...SandboxEgressRefusal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		r.pending = map[string][]SandboxEgressRefusal{}
	}
	r.pending[b.ID] = append(r.pending[b.ID], refusals...)
}

func (r *fakeRefusals) take(b sandboxauth.Binding) []SandboxEgressRefusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, b.SandboxName)
	out := r.pending[b.ID]
	delete(r.pending, b.ID)
	return out
}

func (r *fakeRefusals) takeAsked() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.asked
	r.asked = nil
	return out
}

func webhookRefusal(sandbox string) SandboxEgressRefusal {
	return SandboxEgressRefusal{Host: "webhook.site", Port: 443, Category: "webhook_catcher", What: "webhook catcher",
		Remedy: "the user can allow it for this sandbox with `defenseclaw sandbox unblock webhook.site --sandbox " + sandbox + "`"}
}

// #954: the post-tool hook of a shell or fetch tool call tells the agent
// what the sandbox's egress proxy just refused, in each harness's own
// context field, since a refused CONNECT's 403 body never reaches it. The
// refusals are the binding's own; a pre-tool hook, another tool, a host
// request and a harness without a post-tool context field tell nothing and
// leave them for a later call.
func TestSandboxPostToolHookTellsTheAgentOfEgressRefusals(t *testing.T) {
	refusals := &fakeRefusals{}
	f := newSandboxIngressFixture(t, func(c *SandboxIngressConfig) { c.EgressRefusals = refusals.take })
	type call struct {
		name, path, token, body string
		headers                 []string
		binding                 sandboxauth.Binding
		// context reads the model-facing context out of the answer.
		context func(map[string]interface{}) string
	}
	nested := func(field, event string) func(map[string]interface{}) string {
		return func(resp map[string]interface{}) string {
			out, _ := resp[field].(map[string]interface{})
			specific, _ := out["hookSpecificOutput"].(map[string]interface{})
			if specific["hookEventName"] != event {
				return ""
			}
			s, _ := specific["additionalContext"].(string)
			return s
		}
	}
	flat := func(key string) func(map[string]interface{}) string {
		return func(resp map[string]interface{}) string {
			out, _ := resp["hook_output"].(map[string]interface{})
			s, _ := out[key].(string)
			return s
		}
	}
	mint := func(spec *harness.Spec) (sandboxauth.Binding, string) {
		t.Helper()
		contract := connector.ResolveSandboxHookContract(spec.Name, spec.DefaultVersion)
		if contract.Status != connector.HookCompatibilityKnown {
			t.Fatalf("%s %s: no sandbox hook contract: %s", spec.Name, spec.DefaultVersion, contract.Reason)
		}
		return f.mint(t, "dc-refused-"+spec.Name, spec.Name, spec.DefaultVersion, contract.Contract.ContractID, "")
	}
	copilot, copilotTok := mint(harness.Copilot)
	cursor, cursorTok := mint(harness.Cursor)
	devin, devinTok := mint(harness.Devin)
	claudePost := func(event, tool, input string) call {
		return call{name: "claudecode " + event + " " + tool, path: "/api/v1/claude-code/hook", token: f.claudeTok, binding: f.claude,
			body: `{"hook_event_name":"` + event + `","session_id":"s-claude","tool_name":"` + tool + `","tool_input":` + input + `,` +
				`"tool_response":{"stdout":"","stderr":"curl: (56) CONNECT tunnel failed, response 403"},"tool_use_id":"t-claude","cwd":"/work/app"}`,
			context: nested("claude_code_output", event)}
	}
	curl := `{"command":"curl -sS https://webhook.site/abc"}`
	for _, c := range []call{
		claudePost("PostToolUse", "Bash", curl),
		claudePost("PostToolUseFailure", "Bash", curl),
		claudePost("PostToolUse", "WebFetch", `{"url":"https://webhook.site/abc","prompt":"summarize"}`),
		claudePost("PostToolUse", "mcp__fetch__fetch", `{"url":"https://webhook.site/abc"}`),
		{name: "codex", path: "/api/v1/codex/hook", token: f.codexTok, binding: f.codex,
			headers: []string{"X-DefenseClaw-Hook-Event", "PostToolUse", "X-DefenseClaw-Hook-Contract", "codex-hooks-v1"},
			body: `{"hook_event_name":"PostToolUse","session_id":"s-codex","turn_id":"t1","tool_name":"Bash","tool_input":` + curl + `,` +
				`"tool_response":"curl: (56) CONNECT tunnel failed, response 403","tool_use_id":"t-codex","cwd":"/work/app"}`,
			context: nested("codex_output", "PostToolUse")},
		{name: "copilot", path: "/api/v1/copilot/hook", token: copilotTok, binding: copilot,
			headers: []string{"X-DefenseClaw-Copilot-Event", "postToolUse"},
			body: `{"sessionId":"506e99d3-3a4f-4a7c-9d0e-0f2c6d1e8b11","timestamp":1790483551012,"cwd":"/work/app","toolName":"bash",` +
				`"toolArgs":{"command":"curl -sS https://webhook.site/abc"},"toolResult":{"resultType":"failure","textResultForLlm":"curl: (56)"}}`,
			context: flat("additionalContext")},
		{name: "cursor", path: "/api/v1/cursor/hook", token: cursorTok, binding: cursor,
			body: `{"hook_event_name":"postToolUse","conversation_id":"c1","generation_id":"g1","tool_name":"Shell",` +
				`"tool_input":` + curl + `,"tool_output":"curl: (56)","tool_use_id":"t-cursor","cwd":"/work/app"}`,
			context: flat("additional_context")},
		{name: "devin", path: "/api/v1/devin/hook", token: devinTok, binding: devin,
			body: `{"hook_event_name":"PostToolUse","session_id":"s1","prompt_id":"p1","cwd":"/work/app","tool_name":"exec",` +
				`"tool_input":` + curl + `,"tool_response":{"output":"curl: (56)"}}`,
			context: nested("hook_output", "PostToolUse")},
	} {
		t.Run(c.name, func(t *testing.T) {
			refusals.takeAsked()
			refusals.add(c.binding, webhookRefusal(c.binding.SandboxName))
			resp := f.hook(t, c.path, c.token, c.body, c.headers...)
			got := c.context(resp)
			want := "DefenseClaw's egress policy just blocked this sandbox's HTTPS connection to webhook.site (webhook catcher); " +
				"a tool sees only a connection error, not the reason. The user can allow it for this sandbox with " +
				"`defenseclaw sandbox unblock webhook.site --sandbox " + c.binding.SandboxName + "`. " +
				"Tell the user if the task needs it, and do not try to reach it another way."
			if !strings.HasSuffix(got, want) || resp["action"] == "block" {
				t.Fatalf("answer = %v\ncontext %q\nwant it to end with %q", resp, got, want)
			}
			if asked := refusals.takeAsked(); !slices.Equal(asked, []string{c.binding.SandboxName}) {
				t.Fatalf("asked for %q", asked)
			}
			// Told once: the next call has nothing to add.
			if got := c.context(f.hook(t, c.path, c.token, c.body, c.headers...)); strings.Contains(got, "egress policy") {
				t.Fatalf("told again: %q", got)
			}
		})
	}

	// What does not ask: a pre-tool hook, a tool that does not reach the
	// network, a harness whose post-tool hook has no context field.
	_, hermesTok := f.mint(t, "dc-refused-hermes", "hermes", "0.19.0", "hermes-hooks-v1", "")
	refusals.takeAsked()
	refusals.add(f.claude, webhookRefusal(f.claude.SandboxName))
	for _, c := range []call{
		{name: "pre-tool", path: "/api/v1/claude-code/hook", token: f.claudeTok,
			body: `{"hook_event_name":"PreToolUse","session_id":"s-claude","tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"t2","cwd":"/work/app"}`},
		{name: "read", path: "/api/v1/claude-code/hook", token: f.claudeTok,
			body: `{"hook_event_name":"PostToolUse","session_id":"s-claude","tool_name":"Read","tool_input":{"file_path":"/work/app/a.go"},` +
				`"tool_response":"package a","tool_use_id":"t3","cwd":"/work/app"}`},
		{name: "hermes", path: "/api/v1/hermes/hook", token: hermesTok,
			body: `{"hook_event_name":"post_tool_call","tool_name":"terminal","tool_input":{"command":"curl https://webhook.site/abc"},` +
				`"session_id":"20260929_1","cwd":"/work/app","extra":{"tool_call_id":"call_1","task_id":"t1"}}`},
	} {
		resp := f.hook(t, c.path, c.token, c.body)
		answer, _ := json.Marshal(resp)
		if asked := refusals.takeAsked(); len(asked) != 0 || strings.Contains(string(answer), "egress policy") {
			t.Fatalf("%s: asked %q, answer %s", c.name, asked, answer)
		}
	}
	// The refusals wait for the binding's next shell call.
	resp := f.hook(t, "/api/v1/claude-code/hook", f.claudeTok, claudePost("PostToolUse", "Bash", `{"command":"pip install requests"}`).body)
	if got := nested("claude_code_output", "PostToolUse")(resp); !strings.Contains(got, "webhook.site (webhook catcher)") {
		t.Fatalf("the waiting refusal = %v", resp)
	}
}

// A block keeps its own answer and leaves the refusals for the next call;
// several refusals are listed, the rest counted; the audit row names what
// the agent was told.
// GAP-0216: an SSH refusal's note gives the agent the HTTPS way, and does
// not tell it to leave the destination alone.
// GAP-0325: OpenShell's record of a refused direct connection can come
// after the post-tool hook of the call it failed. A result that names a
// connection error to this machine's sandbox address waits briefly for it,
// so the agent hears that the ask waits for the user, not nothing.
func TestSandboxPostToolHookWaitsForADirectRefusal(t *testing.T) {
	var once sync.Once
	ready := time.Now().Add(200 * time.Millisecond)
	ask := SandboxEgressRefusal{Host: "host.openshell.internal", Port: 8765, Category: manager.NoteAsked, Note: manager.NoteAsked}
	f := newSandboxIngressFixture(t, func(c *SandboxIngressConfig) {
		c.EgressRefusals = func(sandboxauth.Binding) []SandboxEgressRefusal {
			var out []SandboxEgressRefusal
			if time.Now().After(ready) {
				once.Do(func() { out = []SandboxEgressRefusal{ask} })
			}
			return out
		}
	})
	body := `{"hook_event_name":"PostToolUse","session_id":"s-claude","tool_name":"Bash","tool_input":{"command":"npx vitest run"},` +
		`"tool_response":{"stdout":"","stderr":"Error: connect EACCES 198.18.0.2:8765 - Local (0.0.0.0:0)"},"tool_use_id":"t-claude","cwd":"/work/app"}`
	resp := f.hook(t, "/api/v1/claude-code/hook", f.claudeTok, body)
	out, _ := resp["claude_code_output"].(map[string]interface{})
	specific, _ := out["hookSpecificOutput"].(map[string]interface{})
	if s, _ := specific["additionalContext"].(string); !strings.Contains(s, "waits for the user") {
		t.Fatalf("answer = %v", resp)
	}
}

func TestSandboxEgressRefusalNoticeOfSSH(t *testing.T) {
	got := sandboxEgressRefusalNotice([]SandboxEgressRefusal{{Host: "github.com", Port: 22, Category: "ssh", Note: manager.NoteSSH,
		What: "SSH, which does not leave a sandbox", Remedy: "use HTTPS instead: a git remote https://github.com/OWNER/REPO.git"}})
	if !strings.Contains(got, "SSH connection to github.com:22 was refused: SSH does not leave a DefenseClaw sandbox") ||
		!strings.Contains(got, "Use HTTPS instead: a git remote https://github.com/OWNER/REPO.git.") || strings.Contains(got, "another way") {
		t.Fatalf("note = %q", got)
	}
	// GAP-0268, GAP-0236: an ask that holds the connection, and one the
	// user declined, read as such, not as a network error.
	port := SandboxEgressRefusal{Host: "host.openshell.internal", Port: 8765}
	asked, declined := port, port
	asked.Note, declined.Note = manager.NoteAsked, manager.NoteDeclined
	if got := sandboxEgressRefusalNotice([]SandboxEgressRefusal{asked}); !strings.Contains(got,
		"connection to port 8765 on the user's machine (host.openshell.internal:8765) waits for the user") {
		t.Fatalf("asked note = %q", got)
	}
	if got := sandboxEgressRefusalNotice([]SandboxEgressRefusal{declined}); !strings.Contains(got,
		"The user declined this sandbox's connection to port 8765 on the user's machine") {
		t.Fatalf("declined note = %q", got)
	}
	// GAP-0326: a port the run did not declare names the flag, as the feed.
	closed := port
	closed.Note, closed.What = manager.NotePortClosed, "a port on the user's machine the run did not declare"
	closed.Remedy = "tell the user: running the sandbox again with --host-port 8765 makes DefenseClaw ask them about it"
	if got := sandboxEgressRefusalNotice([]SandboxEgressRefusal{closed}); !strings.Contains(got,
		"connection to port 8765 on the user's machine (host.openshell.internal:8765) was refused (a port on the user's machine the run did not declare)") ||
		!strings.Contains(got, "Tell the user: running the sandbox again with --host-port 8765") {
		t.Fatalf("closed note = %q", got)
	}
}

func TestSandboxEgressRefusalNotice(t *testing.T) {
	refusals := &fakeRefusals{}
	f := newSandboxIngressFixture(t, func(c *SandboxIngressConfig) { c.EgressRefusals = refusals.take })
	ctx := withSandboxCoverage(sandboxCtx(f.claude))
	profile := connector.HookProfile{Name: "claudecode"}
	req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PostToolUse", ToolName: "Bash",
		ToolArgs: []byte(`{"command":"npm install"}`)}
	body := []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash"}`)
	refusals.add(f.claude, webhookRefusal(f.claude.SandboxName))
	blocked := agentHookResponse{Action: "block", RawAction: "block", Severity: "HIGH", Reason: "Blocked by DefenseClaw rule X."}
	if got := f.api.addSandboxEgressRefusals(ctx, profile, "claudecode", req, body, nil, blocked); got.AdditionalContext != "" ||
		len(refusals.takeAsked()) != 0 {
		t.Fatalf("a block = %+v", got)
	}
	refusals.add(f.claude,
		SandboxEgressRefusal{Host: "registry.example", Port: 8443, Category: "port_not_allowed", What: "port the proxy does not relay",
			Remedy: "only the user's DefenseClaw operator can add the port (openshell.egress.ports)"},
		SandboxEgressRefusal{Host: "10.1.2.3", Port: 443, Category: "private_network", What: "private network",
			Remedy: "only the user's DefenseClaw operator can open it (openshell.egress.allow)"},
		SandboxEgressRefusal{Host: "pastebin.com", Port: 443, Category: "paste_site", What: "paste site", Remedy: "x"})
	flagged := agentHookResponse{Action: "alert", RawAction: "alert", Severity: "MEDIUM", AdditionalContext: "DefenseClaw observed a finding."}
	got := f.api.addSandboxEgressRefusals(ctx, profile, "claudecode", req, body, nil, flagged)
	want := "DefenseClaw observed a finding.\n\n" +
		"DefenseClaw's egress policy just blocked these connections from this sandbox; a tool sees only a connection error, not the reason:\n" +
		"- webhook.site (webhook catcher): the user can allow it for this sandbox with `defenseclaw sandbox unblock webhook.site --sandbox dc-claude-app`.\n" +
		"- registry.example:8443 (port the proxy does not relay): only the user's DefenseClaw operator can add the port (openshell.egress.ports).\n" +
		"- 10.1.2.3 (private network): only the user's DefenseClaw operator can open it (openshell.egress.allow).\n" +
		"- and 1 more\n" +
		"Tell the user if the task needs them, and do not try to reach them another way."
	specific, _ := got.HookOutput["hookSpecificOutput"].(map[string]interface{})
	if got.AdditionalContext != want || specific["additionalContext"] != want || got.Action != "alert" {
		t.Fatalf("context = %q\nwant      %q\noutput %v", got.AdditionalContext, want, got.HookOutput)
	}
	extra := hookRequestAuditExtra(ctx, connector.HookProfile{})
	if extra[sandboxEgressRefusalExtra] != "webhook.site:webhook_catcher,registry.example:port_not_allowed,10.1.2.3:private_network,pastebin.com:paste_site" {
		t.Fatalf("audit extra = %v", extra)
	}
	// A host request is never told, and neither is a sandbox without the
	// manager's lookup.
	refusals.add(f.claude, webhookRefusal(f.claude.SandboxName))
	if got := f.api.addSandboxEgressRefusals(withSandboxCoverage(t.Context()), profile, "claudecode", req, body, nil,
		agentHookResponse{Action: "allow"}); got.AdditionalContext != "" {
		t.Fatalf("a host request = %+v", got)
	}
	if got := (&APIServer{}).addSandboxEgressRefusals(ctx, profile, "claudecode", req, body, nil,
		agentHookResponse{Action: "allow"}); got.AdditionalContext != "" {
		t.Fatalf("no lookup = %+v", got)
	}
}

func TestSandboxEgressNoticeTool(t *testing.T) {
	for _, tc := range []struct {
		connector, tool string
		want            bool
	}{
		{"claudecode", "Bash", true}, {"claudecode", "WebFetch", true}, {"claudecode", "mcp__fetch__fetch", true},
		{"claudecode", "mcp__web__fetch_url", true}, {"claudecode", "Read", false}, {"claudecode", "WebSearch", false},
		{"codex", "Bash", true}, {"copilot", "bash", true}, {"copilot", "powershell", true}, {"copilot", "web_fetch", true},
		{"cursor", "Shell", true}, {"devin", "exec", true}, {"devin", "read", false}, {"cursor", "bash", false},
	} {
		if got := sandboxEgressNoticeTool(tc.connector, tc.tool); got != tc.want {
			t.Errorf("sandboxEgressNoticeTool(%s, %s) = %t, want %t", tc.connector, tc.tool, got, tc.want)
		}
	}
}
