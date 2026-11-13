// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-10:GAP-0176. ACP terminal, filesystem, permission and tool frames
// are judged as the tool call they perform, through the hook path's code.
// The values below are placeholders: this file pins the mapping and the
// benign set. Detection parity is acp_action_parity_test.go.

func TestACPFrameToolCallMapping(t *testing.T) {
	type call struct {
		tool, args, cwd string
		unread          bool
	}
	req := func(method string, params string) string {
		return `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":` + params + `}`
	}
	note := func(method string, params string) string {
		return `{"jsonrpc":"2.0","method":"` + method + `","params":` + params + `}`
	}
	perm := func(toolCall string) string {
		return req("session/request_permission", `{"sessionId":"s","toolCall":`+toolCall+`,"options":[]}`)
	}
	update := func(body string) string {
		return note("session/update", `{"sessionId":"s","update":`+body+`}`)
	}
	const tool, other = "/tmp/x", `{"x":1}`
	for _, tc := range []struct {
		name, goos  string
		direction   acp.Direction
		frame       string
		calls       []call
		report      bool // a report of a tool the agent runs itself: not refusable
		prose       string
		notAnAction bool
	}{
		// terminal/create: a shell call.
		{name: "terminal command", frame: req("terminal/create", `{"sessionId":"s","command":"echo ok"}`),
			calls: []call{{tool: "shell", args: `{"command":"echo ok"}`}}},
		{name: "terminal args are quoted for POSIX", goos: "linux",
			frame: req("terminal/create", `{"sessionId":"s","command":"echo","args":["ok","two words","it's"]}`),
			calls: []call{{tool: "shell", args: `{"command":"echo ok 'two words' 'it'\\''s'"}`}}},
		{name: "terminal args are quoted for PowerShell", goos: "windows",
			frame: req("terminal/create", `{"sessionId":"s","command":"echo","args":["ok","two words","it's"]}`),
			calls: []call{{tool: "shell", args: `{"command":"echo ok 'two words' 'it''s'"}`}}},
		{name: "terminal env and cwd on POSIX", goos: "linux",
			frame: req("terminal/create", `{"sessionId":"s","command":"echo","args":["ok"],"env":[{"name":"A","value":"1"}],"cwd":"/tmp"}`),
			calls: []call{{tool: "shell", args: `{"command":"A='1' echo ok"}`, cwd: "/tmp"}}},
		{name: "terminal env on Windows", goos: "windows",
			frame: req("terminal/create", `{"sessionId":"s","command":"echo","args":["ok"],"env":[{"name":"A","value":"1"}]}`),
			calls: []call{{tool: "shell", args: `{"command":"$env:A='1'; echo ok"}`}}},
		{name: "terminal without a command is unknown", frame: req("terminal/create", `{"sessionId":"s","args":["ok"]}`),
			calls: []call{{tool: "shell", unread: true}}},
		{name: "terminal with a blank command is unknown", frame: req("terminal/create", `{"sessionId":"s","command":"  "}`),
			calls: []call{{tool: "shell", unread: true}}},
		{name: "terminal with a bad env name is unknown", frame: req("terminal/create", `{"sessionId":"s","command":"ls","env":[{"name":"A B","value":"1"}]}`),
			calls: []call{{tool: "shell", unread: true}}},
		// fs/*: Read and Write.
		{name: "fs read", frame: req("fs/read_text_file", `{"sessionId":"s","path":"`+tool+`"}`),
			calls: []call{{tool: "Read", args: `{"file_path":"` + tool + `"}`}}},
		{name: "fs write", frame: req("fs/write_text_file", `{"sessionId":"s","path":"`+tool+`","content":"ok"}`),
			calls: []call{{tool: "Write", args: `{"content":"ok","file_path":"` + tool + `"}`}}},
		{name: "fs read without a path is unknown", frame: req("fs/read_text_file", `{"sessionId":"s"}`),
			calls: []call{{tool: "Read", unread: true}}},
		{name: "fs write without content is unknown", frame: req("fs/write_text_file", `{"sessionId":"s","path":"`+tool+`"}`),
			calls: []call{{tool: "Write", unread: true}}},
		// session/request_permission: the tool call it asks about, by kind.
		{name: "permission execute", frame: perm(`{"toolCallId":"t","kind":"execute","title":"Run it","rawInput":{"command":"echo ok","cwd":"/tmp"}}`),
			calls: []call{{tool: "shell", args: `{"command":"echo ok"}`, cwd: "/tmp"}}, prose: "Run it"},
		{name: "permission execute argv", frame: perm(`{"toolCallId":"t","kind":"execute","rawInput":{"command":["echo","two words"]}}`),
			calls: []call{{tool: "shell", args: `{"command":"echo 'two words'"}`}}},
		{name: "permission execute without a command keeps its input", frame: perm(`{"toolCallId":"t","kind":"execute","rawInput":` + other + `}`),
			calls: []call{{tool: "shell", args: other}}},
		{name: "permission read by location", frame: perm(`{"toolCallId":"t","kind":"read","locations":[{"path":"` + tool + `"}]}`),
			calls: []call{{tool: "Read", args: `{"file_path":"` + tool + `"}`}}},
		{name: "permission read by input path", frame: perm(`{"toolCallId":"t","kind":"read","rawInput":{"path":"` + tool + `"}}`),
			calls: []call{{tool: "Read", args: `{"file_path":"` + tool + `"}`}}},
		{name: "permission edit with old and new text", frame: perm(`{"toolCallId":"t","kind":"edit","rawInput":{"path":"` + tool + `","old_string":"a","new_string":"b"}}`),
			calls: []call{{tool: "Edit", args: `{"file_path":"` + tool + `","new_string":"b","old_string":"a"}`}}},
		{name: "permission edit with content", frame: perm(`{"toolCallId":"t","kind":"edit","rawInput":{"path":"` + tool + `","content":"ok"}}`),
			calls: []call{{tool: "Write", args: `{"content":"ok","file_path":"` + tool + `"}`}}},
		{name: "permission edit by location only", frame: perm(`{"toolCallId":"t","kind":"edit","locations":[{"path":"` + tool + `"}]}`),
			calls: []call{{tool: "Write", args: `{"file_path":"` + tool + `"}`}}},
		{name: "permission delete", frame: perm(`{"toolCallId":"t","kind":"delete","locations":[{"path":"` + tool + `"}]}`),
			calls: []call{{tool: "delete_file", args: `{"path":"` + tool + `"}`}}},
		{name: "permission fetch", frame: perm(`{"toolCallId":"t","kind":"fetch","rawInput":{"url":"https://example.com/"}}`),
			calls: []call{{tool: "WebFetch", args: `{"url":"https://example.com/"}`}}},
		{name: "permission of another kind is a named tool plus reads of its locations",
			frame: perm(`{"toolCallId":"t","kind":"search","title":"Search files","rawInput":` + other + `,"locations":[{"path":"` + tool + `"}]}`),
			calls: []call{{tool: "acp_search", args: other}, {tool: "Read", args: `{"file_path":"` + tool + `"}`}}},
		{name: "permission titled with a tool name", frame: perm(`{"toolCallId":"t","kind":"other","title":"grep_search","rawInput":` + other + `}`),
			calls: []call{{tool: "grep_search", args: other}}},
		{name: "permission that shows no action is unknown", frame: perm(`{"toolCallId":"t","kind":"execute"}`),
			calls: []call{{unread: true}}},
		{name: "permission without a tool call is unknown", frame: req("session/request_permission", `{"sessionId":"s","options":[]}`),
			calls: []call{{unread: true}}},
		// session/update: reports of tools the agent runs itself.
		{name: "tool_call report", report: true,
			frame: update(`{"sessionUpdate":"tool_call","toolCallId":"t","kind":"execute","title":"Run it","rawInput":{"command":"echo ok"}}`),
			calls: []call{{tool: "shell", args: `{"command":"echo ok"}`}}, prose: "Run it"},
		{name: "tool_call_update with a location", report: true,
			frame: update(`{"sessionUpdate":"tool_call_update","toolCallId":"t","kind":"read","locations":[{"path":"` + tool + `"}]}`),
			calls: []call{{tool: "Read", args: `{"file_path":"` + tool + `"}`}}},
		{name: "status-only update names no action", frame: update(`{"sessionUpdate":"tool_call_update","toolCallId":"t","status":"completed"}`), notAnAction: true},
		{name: "tool_call without input names no action", frame: update(`{"sessionUpdate":"tool_call","toolCallId":"t","kind":"execute","title":"Run it"}`), notAnAction: true},
		{name: "agent text is not an action", frame: update(`{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"ok"}}`), notAnAction: true},
		// A method of the agent's own.
		{name: "agent method request", frame: req("x/custom", `{"a":"b"}`),
			calls: []call{{tool: "x/custom", args: `{"a":"b"}`}}, prose: "b"},
		{name: "agent method notification", report: true, frame: note("x/custom", `{"a":"b"}`),
			calls: []call{{tool: "x/custom", args: `{"a":"b"}`}}, prose: "b"},
		// Not actions: judged as prose, as before.
		{name: "prompt", direction: acp.ClientToAgent, frame: req("session/prompt", `{"sessionId":"s","prompt":[{"type":"text","text":"ok"}]}`), notAnAction: true},
		{name: "terminal lifecycle", frame: req("terminal/kill", `{"sessionId":"s","terminalId":"t"}`), notAnAction: true},
		{name: "terminal output", frame: req("terminal/output", `{"sessionId":"s","terminalId":"t"}`), notAnAction: true},
		{name: "editor request", direction: acp.ClientToAgent, frame: req("terminal/create", `{"sessionId":"s","command":"echo ok"}`), notAnAction: true},
		{name: "response", frame: `{"jsonrpc":"2.0","id":1,"result":{"content":"ok"}}`, notAnAction: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			direction := tc.direction
			if direction == "" {
				direction = acp.AgentToClient
			}
			msg, err := acp.ParseMessageAllowingNullIDErrors([]byte(tc.frame))
			if err != nil {
				t.Fatalf("frame does not parse: %v", err)
			}
			goos := tc.goos
			if goos == "" {
				goos = "linux"
			}
			got, isAction := acpFrameToolCalls(acp.Evaluation{
				Direction: direction, Surface: acp.Classify(msg, direction), Method: msg.Method, Payload: []byte(tc.frame),
			}, goos)
			if tc.notAnAction {
				if isAction {
					t.Fatalf("frame mapped to %+v, want no action", got)
				}
				return
			}
			if !isAction || len(got.calls) != len(tc.calls) {
				t.Fatalf("action=%v calls=%+v, want %d calls", isAction, got.calls, len(tc.calls))
			}
			if got.enforceable == tc.report {
				t.Errorf("enforceable = %v, want %v", got.enforceable, !tc.report)
			}
			if tc.prose != "" && !strings.Contains(got.prose, tc.prose) {
				t.Errorf("prose = %q, want it to hold %q", got.prose, tc.prose)
			}
			for i, want := range tc.calls {
				have := got.calls[i]
				if have.unread != want.unread || (want.tool != "" && have.tool != want.tool) || have.cwd != want.cwd {
					t.Errorf("call %d = %+v, want %+v", i, have, want)
				}
				if want.args != "" {
					assertJSONEqual(t, string(have.args), want.args)
				}
			}
		})
	}
}

func assertJSONEqual(t *testing.T, got, want string) {
	t.Helper()
	var left, right any
	if err := json.Unmarshal([]byte(got), &left); err != nil {
		t.Errorf("args %q are not JSON: %v", got, err)
		return
	}
	if err := json.Unmarshal([]byte(want), &right); err != nil {
		t.Fatalf("test want %q: %v", want, err)
	}
	if a, b := mustJSONString(left), mustJSONString(right); a != b {
		t.Errorf("args = %s, want %s", a, b)
	}
}

func mustJSONString(value any) string {
	out, _ := json.Marshal(value)
	return string(out)
}

// acpActionEnv is the gateway an ACP action frame is evaluated by, and the
// Kiro hook handler of the same configuration, under one rule pack: the two
// surfaces of one connector (Kiro runs both).
type acpActionEnv struct {
	acpAPI  *APIServer
	capture *proxyCanonicalCapture
	hookAPI *APIServer
	project string
	mode    acp.Mode
	// sessionCWD is the directory the editor gave the session, as the guard
	// sends it (Evaluation.SessionCWD): the project, unless a test changes it.
	sessionCWD string
}

func newACPActionEnv(t *testing.T, pack string) *acpActionEnv {
	t.Helper()
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(project)
	installToolCallCorpusProfileConnector(t, "kiro", pack)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "kiro"
	cfg.Guardrail.RulePack = pack
	cfg.ACP = config.ACPConfig{
		Enabled: true, Mode: "action", DefaultProfile: "default",
		Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "default"}},
		Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "default"}},
		Profiles: map[string]config.ACPProfile{"default": {
			Mode: "action", AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
		}},
	}
	api, capture := newGuardrailEventV8TestAPI(t)
	previous := liveGuardrailProfiles.Load()
	t.Cleanup(func() { liveGuardrailProfiles.Store(previous) })
	api.scannerCfg = cfg
	api.initGuardrailProfiles(cfg)
	return &acpActionEnv{
		acpAPI: api, capture: capture, project: project, mode: acp.ModeAction, sessionCWD: project,
		hookAPI: &APIServer{scannerCfg: cfg, health: NewSidecarHealth()},
	}
}

// evaluate sends one agent-to-client (or other) ACP frame to the gateway.
func (e *acpActionEnv) evaluate(t *testing.T, direction acp.Direction, frame []byte) acp.Verdict {
	t.Helper()
	response := e.post(t, direction, frame, "")
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var verdict acp.Verdict
	if err := json.Unmarshal(response.Body.Bytes(), &verdict); err != nil {
		t.Fatal(err)
	}
	return verdict
}

// post sends one frame as the guard does and returns the gateway's answer.
// The envelope names the frame's method and surface as the guard read them;
// a frame the guard would not parse at all is sent with the method given by
// asMethod (and surface tool).
func (e *acpActionEnv) post(t *testing.T, direction acp.Direction, frame []byte, asMethod string) *httptest.ResponseRecorder {
	t.Helper()
	evaluation := acp.Evaluation{
		Profile: "default", Mode: e.mode, AgentID: "kiro", ClientID: "zed",
		Direction: direction, Payload: frame, SessionCWD: e.sessionCWD,
	}
	if asMethod != "" {
		evaluation.Method, evaluation.Surface = asMethod, acp.SurfaceTool
	} else {
		msg, err := acp.ParseMessageAllowingNullIDErrors(frame)
		if err != nil {
			t.Fatalf("frame does not parse: %v", err)
		}
		evaluation.Surface, evaluation.Method = acp.Classify(msg, direction), msg.Method
	}
	body, err := json.Marshal(evaluation)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body))
	e.acpAPI.handleACPEvaluate(response, request)
	return response
}

func acpFrameJSON(t *testing.T, id int, method string, params any) []byte {
	t.Helper()
	frame := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
	if id != 0 {
		frame["id"] = id
	}
	out, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestACPBenignSessionsAreNotFlagged: the routine frames of a coding
// session (reads and writes inside the workspace, git, build and test
// commands, and the permission requests and reports for them) are allowed
// without an alert in the default pack. No benign ACP capture exists in the
// owner traces or the round evidence, so the set is written here.
func TestACPBenignSessionsAreNotFlagged(t *testing.T) {
	env := newACPActionEnv(t, "default")
	p := env.project
	type frame struct {
		name      string
		direction acp.Direction
		id        int
		method    string
		params    any
	}
	exec := func(command string) map[string]any {
		return map[string]any{"toolCallId": "t", "kind": "execute", "title": "Run " + command, "rawInput": map[string]any{"command": command}}
	}
	var frames []frame
	for _, command := range []string{
		"git status", "git diff", "git log --oneline -5", "git add -A", "git commit -m wip", "go build ./...", "go test ./...",
		"npm test", "npm run build", "make test", "pytest -q", "python3 -m pytest tests", "ls -la", "pwd", "cat README.md", "echo ok",
		"grep -rn TODO src", "rm -f build/out.o", "mkdir -p build", "gofmt -l .",
	} {
		frames = append(frames,
			frame{"terminal " + command, acp.AgentToClient, 1, "terminal/create", map[string]any{"sessionId": "s", "command": command, "cwd": p}},
			frame{"permission " + command, acp.AgentToClient, 2, "session/request_permission", map[string]any{"sessionId": "s", "toolCall": exec(command), "options": []any{}}},
			frame{"report " + command, acp.AgentToClient, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
				"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "execute", "title": command, "rawInput": map[string]any{"command": command}}}},
		)
	}
	frames = append(frames,
		frame{"terminal with args", acp.AgentToClient, 1, "terminal/create", map[string]any{"sessionId": "s", "command": "git", "args": []string{"diff", "--stat"}, "cwd": p}},
		frame{"terminal with env", acp.AgentToClient, 1, "terminal/create", map[string]any{"sessionId": "s", "command": "go", "args": []string{"test", "./..."},
			"env": []map[string]string{{"name": "CGO_ENABLED", "value": "0"}}, "cwd": p}},
	)
	for _, path := range []string{filepath.Join(p, "README.md"), filepath.Join(p, "src", "main.go"), filepath.Join(p, "go.mod"), filepath.Join(p, "docs", "guide.md")} {
		frames = append(frames,
			frame{"read " + path, acp.AgentToClient, 3, "fs/read_text_file", map[string]any{"sessionId": "s", "path": path}},
			frame{"permission read " + path, acp.AgentToClient, 4, "session/request_permission", map[string]any{"sessionId": "s", "options": []any{},
				"toolCall": map[string]any{"toolCallId": "t", "kind": "read", "locations": []any{map[string]any{"path": path}}}}},
			frame{"permission edit " + path, acp.AgentToClient, 5, "session/request_permission", map[string]any{"sessionId": "s", "options": []any{},
				"toolCall": map[string]any{"toolCallId": "t", "kind": "edit", "locations": []any{map[string]any{"path": path}},
					"rawInput": map[string]any{"path": path, "old_string": "old line", "new_string": "new line"}}}},
		)
	}
	for _, write := range []struct{ path, content string }{
		{filepath.Join(p, "notes.txt"), "meeting notes\n"},
		{filepath.Join(p, "src", "util.go"), "package src\n\nfunc Add(a, b int) int { return a + b }\n"},
		{filepath.Join(p, "docs", "guide.md"), "# Guide\n\nRun `make test` before you push.\n"},
		{filepath.Join(p, "build", "out.txt"), "ok\n"},
		{filepath.Join(p, ".gitignore"), "build/\n*.o\n"},
	} {
		frames = append(frames, frame{"write " + write.path, acp.AgentToClient, 6, "fs/write_text_file",
			map[string]any{"sessionId": "s", "path": write.path, "content": write.content}})
	}
	// Reports and agent text that name no action.
	frames = append(frames,
		frame{"completed report", acp.AgentToClient, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
			"sessionUpdate": "tool_call_update", "toolCallId": "t", "status": "completed"}}},
		frame{"agent text", acp.AgentToClient, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
			"sessionUpdate": "agent_message_chunk", "content": map[string]any{"type": "text", "text": "I ran the tests and they pass."}}}},
		frame{"prompt", acp.ClientToAgent, 7, "session/prompt", map[string]any{"sessionId": "s", "prompt": []any{map[string]any{"type": "text", "text": "Add a unit test for Add."}}}},
	)
	for _, f := range frames {
		verdict := env.evaluate(t, f.direction, acpFrameJSON(t, f.id, f.method, f.params))
		if verdict.Action != "allow" || verdict.RawAction != "allow" || verdict.WouldBlock {
			t.Errorf("%s: verdict %+v, want a plain allow", f.name, verdict)
		}
	}
	t.Logf("%d benign frames, 0 flagged", len(frames))
}

// credentialsFile is the AWS credentials file of the account the tests run
// as, which the packs protect. On Windows the temp directory is not the
// account profile (a process reads its profile once, so the home of a
// test's env is not the one the rules protect after another test ran),
// so a user profile path is used.
func (e *acpActionEnv) credentialsFile() string {
	if runtime.GOOS == "windows" {
		return `C:\Users\alice\.aws\credentials`
	}
	return filepath.Join(filepath.Dir(e.project), ".aws", "credentials")
}

// setMode runs the ACP profile in mode.
func (e *acpActionEnv) setMode(mode acp.Mode) {
	e.mode = mode
	cfg := e.acpAPI.scannerCfg
	profile := cfg.ACP.Profiles["default"]
	profile.Mode = string(mode)
	cfg.ACP.Profiles["default"] = profile
	cfg.ACP.Mode = string(mode)
}

// TestACPActionVerdictSemantics: the hook path's verdicts, on ACP frames.
// A block refuses the frame in action mode, a would-block is allowed and
// logged in observe mode, an alert is allowed, and the report of a tool the
// agent has run itself cannot be refused: its finding is recorded and the
// report is allowed. The files named are the home credential files the packs protect.
func TestACPActionVerdictSemantics(t *testing.T) {
	for _, mode := range []acp.Mode{acp.ModeAction, acp.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			env := newACPActionEnv(t, "default")
			env.setMode(mode)
			creds := env.credentialsFile()
			write := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 1, "fs/write_text_file",
				map[string]any{"sessionId": "s", "path": creds, "content": "x"}))
			read := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 2, "fs/read_text_file",
				map[string]any{"sessionId": "s", "path": creds}))
			report := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s",
				"update": map[string]any{"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "edit",
					"locations": []any{map[string]any{"path": creds}}, "rawInput": map[string]any{"path": creds, "content": "x"}}}))
			if mode == acp.ModeAction {
				if write.Action != "block" || write.WouldBlock {
					t.Errorf("write of a credential file: %+v, want a block", write)
				}
				if read.Action != "alert" || read.RawAction != "alert" {
					t.Errorf("read of a credential file: %+v, want an alert (allowed and logged)", read)
				}
				// The guard cannot refuse what the agent already ran: the report
				// is an alert that would have blocked (raw block, would_block),
				// allowed, severity kept, and the audit row carries it.
				if report.Action != "alert" || report.RawAction != "block" || !report.WouldBlock || report.Severity != "CRITICAL" {
					t.Errorf("report of a write the agent ran: %+v, want an alert of severity CRITICAL that would have blocked", report)
				}
				return
			}
			if write.Action != "allow" || write.RawAction != "block" || !write.WouldBlock {
				t.Errorf("observe, write of a credential file: %+v, want an allowed would-block", write)
			}
			if read.Action != "allow" || read.RawAction != "alert" {
				t.Errorf("observe, read of a credential file: %+v, want an allowed alert", read)
			}
			if report.Action != "allow" || report.RawAction != "block" || !report.WouldBlock || report.Severity != "CRITICAL" {
				t.Errorf("observe, report: %+v, want an allowed would-block of severity CRITICAL", report)
			}
		})
	}
}

// TestACPUnreadActionIsRefused: an action frame that does not carry its
// action in the documented shape is unknown, never clean.
func TestACPUnreadActionIsRefused(t *testing.T) {
	env := newACPActionEnv(t, "default")
	for name, frame := range map[string][]byte{
		"terminal without a command": acpFrameJSON(t, 1, "terminal/create", map[string]any{"sessionId": "s"}),
		"write without a path":       acpFrameJSON(t, 1, "fs/write_text_file", map[string]any{"sessionId": "s", "content": "x"}),
		"permission with no action":  acpFrameJSON(t, 1, "session/request_permission", map[string]any{"sessionId": "s", "toolCall": map[string]any{"toolCallId": "t"}}),
	} {
		verdict := env.evaluate(t, acp.AgentToClient, frame)
		if verdict.Action != "block" || verdict.Severity != "HIGH" {
			t.Errorf("%s: %+v, want a HIGH block", name, verdict)
		}
	}
}

// TestACPBlockOfAReportIsAnAlertThatWouldBlock: a surface that cannot refuse
// (a report of a tool the agent ran) turns a block into an alert, as the
// hook path answers an event outside a connector's block events.
func TestACPBlockOfAReportIsAnAlertThatWouldBlock(t *testing.T) {
	env := newACPActionEnv(t, "default")
	action := acpFrameAction{calls: []acpToolCall{{tool: "shell", unread: true}}}
	verdict, reportOnly := env.acpAPI.inspectACPFrameAction(t.Context(), acp.Evaluation{}, "kiro", action, nil)
	if verdict.Action != "alert" || !reportOnly {
		t.Fatalf("verdict %q reportOnly=%v, want an alert flagged report-only", verdict.Action, reportOnly)
	}
	action.enforceable = true
	if verdict, reportOnly = env.acpAPI.inspectACPFrameAction(t.Context(), acp.Evaluation{}, "kiro", action, nil); verdict.Action != "block" || reportOnly {
		t.Fatalf("enforceable: verdict %q reportOnly=%v, want a block", verdict.Action, reportOnly)
	}
}
