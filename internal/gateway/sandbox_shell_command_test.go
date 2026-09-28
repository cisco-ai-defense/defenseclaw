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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

const workdirMarkerCommand = "echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt"

// workdirShellCall is one connector's shell tool call in the payload shape
// the harness sends. {DIR} is the working directory the call names.
type workdirShellCall struct {
	name, connector, version, contract, path, body string
	headers                                        []string
	dirs                                           []string
}

// workdirShellCalls are the shell tool shapes of the installed harnesses
// whose shell tool names a working directory (OpenCode 1.18 bash workdir,
// Hermes 0.21 terminal workdir, Amp shell_command workdir, Cursor Agent
// preToolUse Shell cwd and beforeShellExecution cwd, Devin 3000.10 exec
// workdir, Kiro CLI 2.24 shell/execute_bash working_dir, agy run_command
// Cwd), with and without the control arguments those tools also report
// (timeouts, background and run modes, labels), and those of the harnesses
// whose shell tool names none.
func workdirShellCalls() []workdirShellCall {
	const c = workdirMarkerCommand
	return []workdirShellCall{
		{
			name: "opencode-bash", connector: "opencode", version: "1.18.10", contract: "opencode-hooks-v1", path: "/api/v1/opencode/hook",
			body: `{"hook_event_name":"tool.execute.before","tool_name":"bash","tool_input":{"command":"` + c + `","timeout":120000,"workdir":"{DIR}"},` +
				`"session_id":"s1","turn_id":"m1","tool_call_id":"c1","agent_name":"build","cwd":"/work/app","load_heartbeat":true,"arguments_authoritative":true,"mcp_identity_status":"not_mcp"}`,
			dirs: []string{"/work/app/sub", "/work/app", "/tmp", "sub"},
		},
		{
			name: "hermes-terminal", connector: "hermes", version: "0.19.0", contract: "hermes-hooks-v1", path: "/api/v1/hermes/hook",
			body: `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"` + c + `","workdir":"{DIR}"},` +
				`"session_id":"20260927_1","cwd":"/work/app","extra":{"tool_call_id":"call_1","task_id":"t1"}}`,
			dirs: []string{"/work/app/sub", "/tmp"},
		},
		{
			name: "amp-shell-command", connector: "amp", version: "0.0.1785334225", contract: "amp-plugin-v1", path: "/api/v1/amp/hook",
			body: `{"hook_event_name":"tool.call","tool_name":"shell_command","tool_input":{"command":"` + c + `","workdir":"{DIR}"},"session_id":"T-1","cwd":"/work/app"}`,
			dirs: []string{"/work/app/sub", "/tmp"},
		},
		{
			// Cursor reports the call's working_directory as both cwds, ""
			// when the model named none.
			name: "cursor-pretooluse-shell", connector: "cursor", version: "2026.07.23-e383d2b", contract: "cursor-hooks-v1", path: "/api/v1/cursor/hook",
			body: `{"conversation_id":"c1","generation_id":"g1","model":"m","hook_event_name":"preToolUse","cursor_version":"2026.07.23-e383d2b",` +
				`"workspace_roots":["/work/app"],"session_id":"s1","tool_name":"Shell","tool_input":{"command":"` + c + `","cwd":"{DIR}","timeout":30000},` +
				`"tool_use_id":"t1","cwd":"{DIR}"}`,
			dirs: []string{"/work/app/sub", "/work/app", ""},
		},
		{
			name: "cursor-beforeshellexecution", connector: "cursor", version: "2026.07.23-e383d2b", contract: "cursor-hooks-v1", path: "/api/v1/cursor/hook",
			body: `{"conversation_id":"c1","generation_id":"g1","model":"m","hook_event_name":"beforeShellExecution","cursor_version":"2026.07.23-e383d2b",` +
				`"workspace_roots":["/work/app"],"session_id":"s1","command":"` + c + `","cwd":"{DIR}","sandbox":false}`,
			dirs: []string{"/work/app", "/work/app/sub"},
		},
		{
			// Devin sends no session directory of its own; the committed
			// fixture's top-level cwd is kept so the call's differs from it.
			name: "devin-exec", connector: "devin", version: "3000.4.25", contract: "devin-hooks-v1", path: "/api/v1/devin/hook",
			body: `{"hook_event_name":"PreToolUse","session_id":"s1","prompt_id":"p1","cwd":"/work/app","tool_name":"exec","tool_input":{"command":"` + c + `","workdir":"{DIR}"}}`,
			dirs: []string{"/work/app/sub"},
		},
		{
			name: "kiro-shell", connector: "kiro", version: "2.24.1", contract: "kiro-cli-hooks-v1", path: "/api/v1/kiro/hook",
			body: `{"hook_event_name":"preToolUse","cwd":"/work/app","session_id":"s1","tool_name":"shell","tool_input":{"command":"` + c + `","working_dir":"{DIR}"}}`,
			dirs: []string{"/work/app/sub", "/tmp"},
		},
		{
			name: "kiro-execute-bash", connector: "kiro", version: "2.24.1", contract: "kiro-cli-hooks-v1", path: "/api/v1/kiro/hook",
			body: `{"hook_event_name":"preToolUse","cwd":"/work/app","session_id":"s1","tool_name":"execute_bash","tool_input":{"command":"` + c + `","working_dir":"{DIR}"}}`,
			dirs: []string{"/work/app/sub"},
		},
		// The same tools with the control arguments they also report.
		{
			name: "hermes-terminal-controls", connector: "hermes", version: "0.19.0", contract: "hermes-hooks-v1", path: "/api/v1/hermes/hook",
			body: `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"` + c + `","workdir":"{DIR}","background":false,"timeout":60},` +
				`"session_id":"20260927_1","cwd":"/work/app","extra":{"tool_call_id":"call_1","task_id":"t1"}}`,
			dirs: []string{"/work/app/sub"},
		},
		{
			name: "amp-shell-command-timeout", connector: "amp", version: "0.0.1785334225", contract: "amp-plugin-v1", path: "/api/v1/amp/hook",
			body: `{"hook_event_name":"tool.call","tool_name":"shell_command","tool_input":{"command":"` + c + `","workdir":"{DIR}","timeout_ms":10000},"session_id":"T-1","cwd":"/work/app"}`,
			dirs: []string{"/work/app/sub"},
		},
		{
			name: "devin-exec-timeout", connector: "devin", version: "3000.4.25", contract: "devin-hooks-v1", path: "/api/v1/devin/hook",
			body: `{"hook_event_name":"PreToolUse","session_id":"s1","prompt_id":"p1","cwd":"/work/app","tool_name":"exec","tool_input":{"command":"` + c + `","workdir":"{DIR}","timeout":30000}}`,
			dirs: []string{"/work/app/sub"},
		},
		{
			name: "kiro-execute-bash-summary", connector: "kiro", version: "2.24.1", contract: "kiro-cli-hooks-v1", path: "/api/v1/kiro/hook",
			body: `{"hook_event_name":"preToolUse","cwd":"/work/app","session_id":"s1","tool_name":"execute_bash","tool_input":{"command":"` + c + `","summary":"write marker","working_dir":"{DIR}"}}`,
			dirs: []string{"/work/app/sub"},
		},
		{
			name: "antigravity-run-command-bypass-sandbox", connector: "antigravity", version: "1.2.12", contract: "antigravity-hooks-v2", path: "/api/v1/antigravity/hook",
			headers: []string{"X-DefenseClaw-Antigravity-Event", "PreToolUse"},
			body: `{"conversationId":"c1","workspacePaths":["/work/app"],"stepIdx":3,"toolCall":{"name":"run_command","args":{` +
				`"CommandLine":"` + c + `","Cwd":"{DIR}","WaitMsBeforeAsync":500,"BypassSandbox":true,"toolSummary":"write marker","toolAction":"Writing marker"}}}`,
			dirs: []string{"/work/app/sub"},
		},
		{
			name: "antigravity-run-command", connector: "antigravity", version: "1.2.12", contract: "antigravity-hooks-v2", path: "/api/v1/antigravity/hook",
			headers: []string{"X-DefenseClaw-Antigravity-Event", "PreToolUse"},
			body: `{"conversationId":"c1","workspacePaths":["/work/app"],"stepIdx":3,"toolCall":{"name":"run_command","args":{` +
				`"CommandLine":"` + c + `","Cwd":"{DIR}","WaitMsBeforeAsync":500,"toolSummary":"write marker","toolAction":"Writing marker"}}}`,
			dirs: []string{"/work/app/sub"},
		},
		// Controls: these shell tools name no working directory.
		{
			name: "claudecode-bash", connector: "claudecode", version: "2.1.156", contract: "claudecode-hooks-v1", path: "/api/v1/claude-code/hook",
			body: `{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"/work/app","permission_mode":"default","tool_name":"Bash",` +
				`"tool_input":{"command":"` + c + `","description":"write marker","timeout":120000},"tool_use_id":"t1"}`,
			dirs: []string{""},
		},
		{
			// Codex passes only the command of exec_command to its hooks.
			name: "codex-bash", connector: "codex", version: "0.128.0", contract: "codex-hooks-v1", path: "/api/v1/codex/hook",
			headers: []string{"X-DefenseClaw-Hook-Event", "PreToolUse", "X-DefenseClaw-Hook-Contract", "codex-hooks-v1"},
			body:    `{"hook_event_name":"PreToolUse","session_id":"s1","turn_id":"t1","cwd":"/work/app","tool_name":"Bash","tool_input":{"command":"` + c + `"},"tool_use_id":"u1"}`,
			dirs:    []string{""},
		},
		{
			name: "copilot-bash", connector: "copilot", version: "1.0.40", contract: "copilot-hooks-v1", path: "/api/v1/copilot/hook",
			headers: []string{"X-DefenseClaw-Copilot-Event", "preToolUse"},
			body:    `{"sessionId":"s1","timestamp":1790483549431,"cwd":"/work/app","toolName":"bash","toolArgs":{"command":"` + c + `","description":"write marker"}}`,
			dirs:    []string{""},
		},
		{
			// Copilot CLI 1.0.8x bash also reports its run mode and wait.
			name: "copilot-bash-mode", connector: "copilot", version: "1.0.40", contract: "copilot-hooks-v1", path: "/api/v1/copilot/hook",
			headers: []string{"X-DefenseClaw-Copilot-Event", "preToolUse"},
			body: `{"sessionId":"s1","timestamp":1790483549431,"cwd":"/work/app","toolName":"bash","toolArgs":{"command":"` + c + `",` +
				`"description":"write marker","mode":"sync","initial_wait":30}}`,
			dirs: []string{""},
		},
		{
			name: "openhands-terminal", connector: "openhands", version: "1.16.0", contract: "openhands-hooks-v1", path: "/api/v1/openhands/hook",
			body: `{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"` + c + `","is_input":false,"timeout":null,"reset":false,"kind":"TerminalAction"},` +
				`"session_id":"c1c2b756-f8e9-4e9d-97d0-2c27ecb6c3d1","working_dir":"/work/app","metadata":{}}`,
			dirs: []string{""},
		},
		{
			name: "omnigent-sys-os-shell", connector: "omnigent", version: "0.13.0", contract: "omnigent-custom-policy-v1", path: "/api/v1/omnigent/hook",
			body: `{"hook_event_name":"PreToolUse","omnigent_event_type":"tool_call","agent_name":"OmniGent","agent_type":"omnigent",` +
				`"tool_name":"sys_os_shell","tool_input":{"command":"` + c + `"}}`,
			dirs: []string{""},
		},
	}
}

// sandboxShellCallMistyped gives a listed argument of each shell call a
// value of another JSON type, so the connector's projection refuses the
// call. Calls whose tool takes no argument but the command have none.
func sandboxShellCallMistyped(tc workdirShellCall) (string, bool) {
	if strings.Contains(tc.body, `"{DIR}"`) {
		return strings.ReplaceAll(tc.body, `"{DIR}"`, `7`), true
	}
	for _, swap := range [][2]string{
		{`"description":"write marker"`, `"description":["write marker"]`},
		{`"timeout":120000`, `"timeout":"120000"`},
		{`"timeout":null`, `"timeout":"soon"`},
	} {
		if strings.Contains(tc.body, swap[0]) {
			return strings.Replace(tc.body, swap[0], swap[1], 1), true
		}
	}
	return "", false
}

// TestSandboxShellCallsAreJudged pins that the shell tool call of every
// sandboxed harness reaches the command rules, and is blocked with the
// marker rule's plain reason, whatever else the call names:
//   - its own working directory (a subdirectory of the mounted /work/app,
//     the workspace itself, one outside the mount, a relative one). Left as
//     a second working directory next to the request's (mapped to the host
//     project, so even /work/app differs), the trusted-action parse was
//     ambiguous and the CRITICAL match only an allowed candidate;
//   - an argument the connector's projection does not list, or a listed one
//     with a value of another type. Either left the parse partial, so one
//     extra argument turned a block into an allow. The command is now also
//     judged on its own.
func TestSandboxShellCallsAreJudged(t *testing.T) {
	installSandboxMarkerRules(t)
	f := newSandboxIngressFixture(t)
	if err := os.Mkdir(filepath.Join(f.project, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	marker := `"` + workdirMarkerCommand + `"`
	for i, tc := range workdirShellCalls() {
		base := strings.ReplaceAll(tc.body, "{DIR}", "/work/app/sub")
		bodies := map[string]string{
			"unlisted":      strings.Replace(base, marker, marker+`,"dc_unlisted_arg":"x"`, 1),
			"unlisted-null": strings.Replace(base, marker, marker+`,"dc_unlisted_arg":null`, 1),
		}
		if mistyped, ok := sandboxShellCallMistyped(tc); ok {
			bodies["mistyped"] = strings.ReplaceAll(mistyped, "{DIR}", "/work/app/sub")
		}
		for _, dir := range tc.dirs {
			if label := strings.Trim(strings.ReplaceAll(dir, "/", "-"), "-"); label != "" {
				bodies["workdir-"+label] = strings.ReplaceAll(tc.body, "{DIR}", dir)
			} else {
				bodies["workdir-none"] = strings.ReplaceAll(tc.body, "{DIR}", dir)
			}
		}
		for variant, body := range bodies {
			t.Run(tc.name+"/"+variant, func(t *testing.T) {
				if body == base && !strings.HasPrefix(variant, "workdir-") {
					t.Fatal("the variant did not change the call")
				}
				_, token := f.mint(t, "dc-"+tc.connector+"-"+strconv.Itoa(i)+"-"+variant, tc.connector, tc.version, tc.contract, f.project)
				resp := f.hook(t, tc.path, token, body, tc.headers...)
				if resp["action"] != "block" || resp["raw_action"] != "block" {
					t.Fatalf("verdict = %v", resp)
				}
				// Claude Code and Codex render their own reasons.
				if tc.connector != "claudecode" && tc.connector != "codex" && resp["reason"] != sandboxMarkerBlockReason {
					t.Fatalf("reason = %v, want %q", resp["reason"], sandboxMarkerBlockReason)
				}
			})
		}
	}
}

// TestSandboxShellCommandOnlyAddsVerdicts pins that judging a sandbox shell
// call's command alone decides nothing the command does not: a harmless
// command with an extra argument stays allowed, and a marker that appears
// only in a dropped argument, not in the command, is not a block.
func TestSandboxShellCommandOnlyAddsVerdicts(t *testing.T) {
	installSandboxMarkerRules(t)
	f := newSandboxIngressFixture(t)
	for i, args := range []string{
		`{"command":"ls -la","dc_unlisted_arg":"x"}`,
		`{"command":"ls -la","workdir":7}`,
		`{"command":"ls -la","workdir":"/work/app","dc_unlisted_arg":"DCE2E-BLOCK-MARKER"}`,
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			_, token := f.mint(t, "dc-opencode-harmless-"+strconv.Itoa(i), "opencode", "1.18.10", "opencode-hooks-v1", f.project)
			resp := f.hook(t, "/api/v1/opencode/hook", token, `{"hook_event_name":"tool.execute.before","tool_name":"bash","tool_input":`+args+
				`,"session_id":"s1","turn_id":"m1","tool_call_id":"c1","agent_name":"build","cwd":"/work/app","load_heartbeat":true,`+
				`"arguments_authoritative":true,"mcp_identity_status":"not_mcp"}`)
			if resp["action"] == "block" || resp["raw_action"] == "block" {
				t.Fatalf("verdict = %v", resp)
			}
		})
	}
}

func TestSandboxShellCommandScope(t *testing.T) {
	args := json.RawMessage(`{"command":"ls","dc_unlisted_arg":1}`)
	if command, tool := sandboxShellCommand(context.Background(), "opencode", "tool.execute.before", "bash", "bash", args); command != nil || tool != "" {
		t.Fatalf("host request = %s, %q; want none", command, tool)
	}
	ctx := sandboxauth.WithRequest(context.Background(), sandboxTestBinding("opencode"), nil)
	if command, tool := sandboxShellCommand(ctx, "opencode", "tool.execute.before", "bash", "bash", args); string(command) != `{"command":"ls"}` || tool != "bash" {
		t.Fatalf("sandbox request = %s, %q", command, tool)
	}
	// Another connector's binding, and a tool that is not a shell.
	if command, _ := sandboxShellCommand(ctx, "hermes", "pre_tool_call", "terminal", "terminal", args); command != nil {
		t.Fatalf("other connector's binding = %s", command)
	}
	if command, _ := sandboxShellCommand(ctx, "opencode", "tool.execute.before", "read", "read", args); command != nil {
		t.Fatalf("read tool = %s", command)
	}
	// Cursor's beforeShellExecution payload is the call, judged as a shell.
	cursor := sandboxauth.WithRequest(context.Background(), sandboxTestBinding("cursor"), nil)
	if command, tool := sandboxShellCommand(cursor, "cursor", "beforeShellExecution", "tool", "tool",
		json.RawMessage(`{"command":"ls","cwd":7}`)); string(command) != `{"command":"ls"}` || tool != "shell" {
		t.Fatalf("cursor event = %s, %q", command, tool)
	}
}

func TestMergeSandboxShellCommandVerdict(t *testing.T) {
	candidate := RuleFinding{RuleID: "E2E-SANDBOX-MARKER", Title: "E2E sandbox marker command", Severity: "CRITICAL",
		Confidence: 0.99, enforcement: findingEnforcementDetectionOnly}
	proven := candidate
	proven.enforcement = findingEnforcementAllowed
	allow := &ToolInspectVerdict{Action: "allow", Severity: "CRITICAL", Reason: "matched: E2E-SANDBOX-MARKER:E2E sandbox marker command",
		Findings: []string{"E2E-SANDBOX-MARKER:E2E sandbox marker command"}, DetailedFindings: []RuleFinding{candidate}}

	got := mergeSandboxShellCommandVerdict(nil, "opencode", allow, []RuleFinding{proven})
	if got == allow || got.Action != "block" || got.Severity != "CRITICAL" ||
		len(got.DetailedFindings) != 1 || !got.DetailedFindings[0].contributesToEnforcement() ||
		len(got.Findings) != 1 || got.Reason != "matched: E2E-SANDBOX-MARKER:E2E sandbox marker command" {
		t.Fatalf("merged = %+v", got)
	}
	if allow.Action != "allow" || allow.DetailedFindings[0].contributesToEnforcement() {
		t.Fatalf("the call's verdict changed: %+v", allow)
	}
	// A candidate alone, or no finding, adds nothing.
	for _, findings := range [][]RuleFinding{{candidate}, nil} {
		if got := mergeSandboxShellCommandVerdict(nil, "opencode", allow, findings); got != allow {
			t.Fatalf("merged %+v = %+v", findings, got)
		}
	}
	// Never lifts a verdict: a block stays a block whatever the command.
	block := &ToolInspectVerdict{Action: "block", Severity: "HIGH", Findings: []string{"STATIC-BLOCK"}}
	if got := mergeSandboxShellCommandVerdict(nil, "opencode", block, nil); got != block {
		t.Fatalf("block = %+v", got)
	}
	// A new rule is added next to the call's findings and raises severity.
	low := &ToolInspectVerdict{Action: "allow", Severity: "LOW", Findings: []string{"OTHER:Other"},
		DetailedFindings: []RuleFinding{{RuleID: "OTHER", Title: "Other", Severity: "LOW"}}}
	got = mergeSandboxShellCommandVerdict(nil, "opencode", low, []RuleFinding{proven})
	if got.Action != "block" || got.Severity != "CRITICAL" || got.Confidence != 0.99 ||
		len(got.DetailedFindings) != 2 || len(got.Findings) != 2 {
		t.Fatalf("merged = %+v", got)
	}
}

// TestHostShellCallsInTheirOwnWorkdirAreJudged is the host counterpart of
// TestSandboxShellCallsAreJudged, where no command-only fallback applies, so
// it proves each shape's trusted-action mapping: the request's working
// directory is host-sanitized (symlinks resolved), so a call naming the same
// directory unresolved (as on macOS, where the temp directory is under the
// /var symlink), a subdirectory, or a relative subdirectory conflicted with
// it just the same.
func TestHostShellCallsInTheirOwnWorkdirAreJudged(t *testing.T) {
	installSandboxMarkerRules(t)
	session := t.TempDir()
	if err := os.Mkdir(filepath.Join(session, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	registry := connector.NewDefaultRegistry()
	for _, tc := range workdirShellCalls() {
		switch tc.connector {
		case "claudecode", "codex":
			continue // their own hook handlers; covered through the sandbox
		}
		dirs := []string{session, filepath.Join(session, "sub"), "sub"}
		if tc.connector == "antigravity" || tc.connector == "devin" {
			dirs = dirs[:2] // both require an absolute directory
		}
		if !strings.Contains(tc.body, "{DIR}") {
			dirs = []string{""}
		}
		for _, dir := range dirs {
			t.Run(tc.name+"/"+strings.ReplaceAll(strings.TrimPrefix(dir, session), "/", "-"), func(t *testing.T) {
				body := strings.ReplaceAll(strings.ReplaceAll(tc.body, "/work/app", session), "{DIR}", dir)
				var payload map[string]interface{}
				if err := json.Unmarshal([]byte(body), &payload); err != nil {
					t.Fatal(err)
				}
				event := ""
				for i := 0; i+1 < len(tc.headers); i += 2 {
					if strings.HasSuffix(tc.headers[i], "-Event") {
						event = tc.headers[i+1]
					}
				}
				profile := connectorProfileForHostTest(t, registry, tc.connector)
				req := normalizeAgentHookRequestWithRawProfileEvent(tc.connector, payload, []byte(body), profile, event)
				req.CWD = hookCWDForContext(context.Background(), req.CWD)
				store, logger := testStoreAndLogger(t)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = tc.connector
				api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
				resp := api.evaluateAgentHook(context.Background(), req)
				if resp.RawAction != "block" {
					t.Fatalf("%s raw_action = %q (action %q, reason %q)", tc.name, resp.RawAction, resp.Action, resp.Reason)
				}
			})
		}
	}
}

func connectorProfileForHostTest(t *testing.T, registry *connector.Registry, name string) connector.HookProfile {
	t.Helper()
	conn, ok := registry.Get(name)
	if !ok {
		t.Fatalf("no connector %s", name)
	}
	provider, ok := conn.(connector.HookProfileProvider)
	if !ok {
		t.Fatalf("connector %s has no hook profile", name)
	}
	return provider.HookProfile(connector.SetupOpts{})
}

// TestAgentHookTrustedActionShellShapes pins the mapping of shell shapes
// that did not parse completely, so command rules could not prove a trusted
// action and a CRITICAL finding stayed an allowed candidate. The shapes of
// workdirShellCalls are proven end to end by
// TestHostShellCallsInTheirOwnWorkdirAreJudged; these are the other control
// arguments those tools report (connector.TrustedShellArgs) and an empty
// working directory.
func TestAgentHookTrustedActionShellShapes(t *testing.T) {
	for _, tc := range []struct {
		name, connector, tool, args string
	}{
		{"cursor-shell-no-cwd", "cursor", "Shell",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","cwd":""}`},
		{"hermes-terminal-controls", "hermes", "terminal",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","background":true,"timeout":60,"pty":false,"notify":["done"]}`},
		{"devin-exec-controls", "devin", "exec",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","timeout":0,"tty":false}`},
		{"copilot-bash-async", "copilot", "bash",
			`{"command":"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt","description":"write marker","mode":"async","detach":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const sessionCWD = "/work/app/sub"
			raw := actionfacts.Analyze(actionfacts.Input{Tool: tc.tool, Args: json.RawMessage(tc.args), CWD: sessionCWD})
			if raw.Parse.Status == actionfacts.StatusComplete {
				t.Skip("the raw shape now parses completely upstream; the mapping is redundant")
			}
			args, toolCWD := agentHookTrustedActionArgs(tc.connector, tc.tool, json.RawMessage(tc.args))
			mapped := actionfacts.Analyze(actionfacts.Input{
				Tool: agentHookTrustedActionTool(tc.connector, tc.tool, "linux"),
				Args: args,
				CWD:  agentHookTrustedActionCWD(context.Background(), sessionCWD, toolCWD),
			})
			if mapped.Parse.Status != actionfacts.StatusComplete {
				t.Fatalf("mapped parse = %+v, want complete", mapped.Parse)
			}
		})
	}
	// Scoped to the one connector each: nobody else's tool or arguments move.
	if got := agentHookTrustedActionTool("hermes", "sys_os_shell", "linux"); got != "sys_os_shell" {
		t.Errorf("hermes sys_os_shell = %q, want passthrough", got)
	}
	args := json.RawMessage(`{"command":"ls","is_input":false}`)
	if got, cwd := agentHookTrustedActionArgs("hermes", "terminal", args); string(got) != string(args) || cwd != "" {
		t.Errorf("hermes terminal args = %s (cwd %q), want passthrough", got, cwd)
	}
	// Input to a running process is judged as shell input.
	if got, _ := agentHookTrustedActionArgs("openhands", "terminal", json.RawMessage(`{"command":"ls","is_input":true}`)); string(got) != `{"command":"ls"}` {
		t.Errorf("input to a running process was not projected: %s", got)
	}
	// The tool call's directory replaces the session's, mapped the same way
	// (on the host: an existing absolute directory, symlinks resolved).
	if got := agentHookTrustedActionCWD(context.Background(), "/work/app", ""); got != "/work/app" {
		t.Errorf("no tool cwd = %q, want the request's", got)
	}
	dir := t.TempDir()
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := agentHookTrustedActionCWD(context.Background(), "/work/app", dir); got != want {
		t.Errorf("tool cwd = %q, want %q", got, want)
	}
	if got := agentHookTrustedActionCWD(context.Background(), "/work/app", filepath.Join(dir, "missing")); got != "" {
		t.Errorf("missing tool cwd = %q, want none", got)
	}
	// A relative directory is resolved against the session's; one the
	// gateway cannot place is none.
	if err := os.Mkdir(filepath.Join(want, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := agentHookTrustedActionCWD(context.Background(), want, "sub"); got != filepath.Join(want, "sub") {
		t.Errorf("relative tool cwd = %q, want %q", got, filepath.Join(want, "sub"))
	}
	for _, tc := range []struct{ request, tool string }{{"", "sub"}, {want, "~/sub"}, {want, "missing"}} {
		if got := agentHookTrustedActionCWD(context.Background(), tc.request, tc.tool); got != "" {
			t.Errorf("tool cwd %q in %q = %q, want none", tc.tool, tc.request, got)
		}
	}
}

// TestSandboxHookOnlyShellCallsAreJudged pins that the shell tool calls and
// running-process input the hook-only harnesses send, in their exact payload
// shapes, reach the command rules through the sandbox ingress: the E2E
// marker rule must block them with its plain reason, rendered in the
// harness's own block shape. TestSandboxShellCallsAreJudged covers the
// other shell shapes.
func TestSandboxHookOnlyShellCallsAreJudged(t *testing.T) {
	installSandboxMarkerRules(t)
	var obs sandboxObserver
	// Mount mode, as the E2E runs: the request working directory /work/app
	// maps to a host directory.
	f := newSandboxIngressFixture(t, obs.observe)
	const command = "echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt"
	for i, tc := range []struct {
		connector, version, contract, path, body, tool string
		headers                                        []string
		// decision is the harness's own rendering of the block, if checked;
		// reason says whether that rendering carries the plain reason too.
		decision string
		reason   bool
	}{
		{
			connector: "hermes", version: "0.19.0", contract: "hermes-hooks-v1", path: "/api/v1/hermes/hook", tool: "terminal",
			body: `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"` + command + `"},` +
				`"session_id":"20260927_1","cwd":"/work/app","extra":{"tool_call_id":"call_1","task_id":"t1"}}`,
			decision: "block", reason: true,
		},
		{
			connector: "openhands", version: "1.16.0", contract: "openhands-hooks-v1", path: "/api/v1/openhands/hook", tool: "terminal",
			body: `{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"` + command + `","is_input":false,` +
				`"timeout":null,"reset":false,"kind":"TerminalAction"},"tool_response":null,"message":null,` +
				`"session_id":"c1c2b756-f8e9-4e9d-97d0-2c27ecb6c3d1","working_dir":"/work/app","metadata":{}}`,
			decision: "deny", reason: true,
		},
		{
			connector: "antigravity", version: "1.2.12", contract: "antigravity-hooks-v2", path: "/api/v1/antigravity/hook", tool: "run_command",
			headers: []string{"X-DefenseClaw-Antigravity-Event", "PreToolUse"},
			// agy 1.2's run_command schema requires WaitMsBeforeAsync,
			// toolSummary and toolAction next to CommandLine and Cwd.
			body: `{"conversationId":"c1","workspacePaths":["/work/app"],"stepIdx":3,"toolCall":{"name":"run_command","args":{` +
				`"CommandLine":"` + command + `","Cwd":"/tmp","WaitMsBeforeAsync":500,` +
				`"toolSummary":"write marker","toolAction":"Writing marker"}}}`,
			decision: "deny",
		},
		// Text sent to a running process is judged as shell input.
		{
			connector: "openhands", version: "1.16.0", contract: "openhands-hooks-v1", path: "/api/v1/openhands/hook", tool: "terminal",
			body: `{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"` + command + `","is_input":true,` +
				`"timeout":null,"reset":false,"kind":"TerminalAction"},"session_id":"c1c2b756-f8e9-4e9d-97d0-2c27ecb6c3d1","working_dir":"/work/app"}`,
		},
		{
			connector: "antigravity", version: "1.2.12", contract: "antigravity-hooks-v2", path: "/api/v1/antigravity/hook", tool: "send_command_input",
			headers: []string{"X-DefenseClaw-Antigravity-Event", "PreToolUse"},
			body: `{"conversationId":"c1","workspacePaths":["/work/app"],"stepIdx":4,"toolCall":{"name":"send_command_input","args":{` +
				`"CommandId":"cmd-1","Input":"` + command + `","WaitMs":500,"toolSummary":"type","toolAction":"Typing"}}}`,
		},
		{
			connector: "hermes", version: "0.19.0", contract: "hermes-hooks-v1", path: "/api/v1/hermes/hook", tool: "process",
			body: `{"hook_event_name":"pre_tool_call","tool_name":"process","tool_input":{"action":"submit","session_id":"proc_1","data":"` + command + `"},` +
				`"session_id":"20260927_1","cwd":"/work/app","extra":{"tool_call_id":"call_2","task_id":"t1"}}`,
		},
	} {
		t.Run(tc.connector+"-"+tc.tool, func(t *testing.T) {
			name := "dc-" + tc.connector + "-" + strings.ReplaceAll(tc.tool, "_", "-") + "-" + strconv.Itoa(i)
			_, token := f.mint(t, name, tc.connector, tc.version, tc.contract, t.TempDir())
			obs.take()
			resp := f.hook(t, tc.path, token, tc.body, tc.headers...)
			out, _ := resp["hook_output"].(map[string]interface{})
			if resp["action"] != "block" || resp["reason"] != sandboxMarkerBlockReason ||
				(tc.decision != "" && out["decision"] != tc.decision) || (tc.reason && out["reason"] != sandboxMarkerBlockReason) {
				t.Fatalf("%s verdict = %v", tc.connector, resp)
			}
			if decisions, _ := obs.take(); len(decisions) != 1 || decisions[0].Action != "block" || decisions[0].Tool != tc.tool {
				t.Fatalf("decisions = %+v", decisions)
			}
		})
	}
}
