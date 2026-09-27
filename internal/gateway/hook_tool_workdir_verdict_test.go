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
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

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

// TestSandboxShellCallsInTheirOwnWorkdirAreJudged pins that a sandboxed
// harness's shell tool call naming its own working directory is judged in
// that directory, and that its command still reaches the command rules. The
// request's working directory is the session's, /work/app, mounted from a
// host project; the call names a subdirectory of it, the workspace itself,
// a directory outside the mount, or a relative one. Left as a second working
// directory next to the request's (which is mapped to the host project, so
// even /work/app differs), the trusted-action parse was ambiguous (or
// partial, for a key the parser does not read as a directory), and the
// CRITICAL marker rule's match was an allowed candidate.
func TestSandboxShellCallsInTheirOwnWorkdirAreJudged(t *testing.T) {
	installSandboxMarkerRules(t)
	f := newSandboxIngressFixture(t)
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(project, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i, tc := range workdirShellCalls() {
		for j, dir := range tc.dirs {
			label := strings.Trim(strings.ReplaceAll(dir, "/", "-"), "-")
			if label == "" {
				label = "none"
			}
			t.Run(tc.name+"/"+label, func(t *testing.T) {
				_, token, err := f.store.Mint(sandboxauth.Spec{
					SandboxName: "dc-" + tc.connector + "-wd-" + strconv.Itoa(i) + "-" + strconv.Itoa(j), Connector: tc.connector,
					AgentVersion: tc.version, HookContractID: tc.contract, PolicyProfile: "open",
					Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirMount,
						Mounts: []sandboxauth.Mount{{SandboxPath: "/work/app", HostPath: project}}},
					HostUser: sandboxauth.HostUser{UID: "1000", Name: "dev"},
				})
				if err != nil {
					t.Fatal(err)
				}
				rec := f.do(t, http.MethodPost, tc.path, token, strings.ReplaceAll(tc.body, "{DIR}", dir), tc.headers...)
				if rec.Code != http.StatusOK {
					t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
				}
				var resp map[string]interface{}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatal(err)
				}
				if resp["action"] != "block" || resp["raw_action"] != "block" {
					t.Fatalf("verdict = %s", rec.Body.String())
				}
			})
		}
	}
}

// TestHostShellCallsInTheirOwnWorkdirAreJudged is the host counterpart: the
// request's working directory is host-sanitized (symlinks resolved), so a
// call naming the same directory unresolved (as on macOS, where the temp
// directory is under the /var symlink), a subdirectory, or a relative
// subdirectory conflicted with it just the same.
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
