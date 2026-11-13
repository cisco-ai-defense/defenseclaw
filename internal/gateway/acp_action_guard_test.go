// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
)

// Review findings of rel-1-0-10:GAP-0176 (GAP-0295, GAP-0296, GAP-0297 and
// the Kiro-shaped edit input). Like the parity test, the actions are not
// written here: they are the shell, Write and Edit cases of the existing
// fixtures (testdata/acp_parity_cases.jsonl, by case id), re-framed.

func acpBlocked(raw string) bool {
	decided := normalizeCodexAction(raw)
	return decided == "block" || decided == "confirm"
}

func acpJSONText(t *testing.T, value any) string {
	t.Helper()
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestACPFrameWithKeysThatDifferOnlyInCaseIsRefused: encoding/json reads
// "Command" and "command" as one field and keeps the last, while the editor
// reads the exact key. A twin key after the real one made the guard judge one
// action and the editor run another, for every blocked fixture frame
// (GAP-0295). The parser now refuses such a frame, in params and on the
// envelope, and the gateway refuses it too.
func TestACPFrameWithKeysThatDifferOnlyInCaseIsRefused(t *testing.T) {
	pairs, _ := acpParityPairs(t, loadACPParityCases(t))
	env := newACPActionEnv(t, "default")
	benign := filepath.Join(env.project, "notes.txt")
	cwd := acpJSONText(t, env.project)
	var blocked, refused int
	check := func(id, frame string, asMethod string) {
		t.Helper()
		if _, err := acp.ParseMessage([]byte(frame)); err == nil {
			t.Errorf("%s: the guard parses a frame with a twin key: %.200s", id, frame)
			return
		}
		if response := env.post(t, acp.AgentToClient, []byte(frame), asMethod); response.Code != http.StatusBadRequest {
			t.Errorf("%s: the gateway answers %d to a frame with a twin key, want 400", id, response.Code)
			return
		}
		refused++
	}
	for _, pair := range pairs {
		var control string
		var twins []struct{ name, frame string }
		switch pair.method {
		case "terminal/create":
			command := acpJSONText(t, pair.params["command"])
			params := `{"sessionId":"s","command":` + command + `,"cwd":` + cwd + `}`
			control = `{"jsonrpc":"2.0","id":1,"method":"terminal/create","params":` + params + `}`
			twins = []struct{ name, frame string }{
				{"Command", `{"jsonrpc":"2.0","id":1,"method":"terminal/create","params":{"sessionId":"s","command":` + command + `,"Command":"echo ok","cwd":` + cwd + `}}`},
				{"Method", `{"jsonrpc":"2.0","id":1,"method":"terminal/create","Method":"terminal/output","params":` + params + `}`},
				{"Params", `{"jsonrpc":"2.0","id":1,"method":"terminal/create","params":` + params + `,"Params":{"sessionId":"s","command":"echo ok"}}`},
			}
		case "fs/write_text_file":
			path, content := acpJSONText(t, pair.params["path"]), acpJSONText(t, pair.params["content"])
			control = `{"jsonrpc":"2.0","id":1,"method":"fs/write_text_file","params":{"sessionId":"s","path":` + path + `,"content":` + content + `}}`
			twins = []struct{ name, frame string }{
				{"Path", `{"jsonrpc":"2.0","id":1,"method":"fs/write_text_file","params":{"sessionId":"s","path":` + path + `,"Path":` + acpJSONText(t, benign) + `,"content":` + content + `}}`},
				{"Content", `{"jsonrpc":"2.0","id":1,"method":"fs/write_text_file","params":{"sessionId":"s","path":` + path + `,"content":` + content + `,"Content":"ok"}}`},
			}
		default:
			continue
		}
		if !acpBlocked(env.evaluate(t, acp.AgentToClient, []byte(control)).RawAction) {
			continue
		}
		blocked++
		for _, twin := range twins {
			check(pair.id+" "+twin.name, twin.frame, pair.method)
		}
	}
	if blocked < 60 {
		t.Fatalf("only %d fixture frames are blocked: the rules did not load?", blocked)
	}
	t.Logf("%d blocked fixture frames, %d twin-key variants refused", blocked, refused)
}

// TestACPPermissionPastTheLocationBoundIsRefused: a permission that names
// more locations than the guard judges is refused whole (never judged in
// part): the credential file named after the bound is not allowed through
// (GAP-0296).
func TestACPPermissionPastTheLocationBoundIsRefused(t *testing.T) {
	env := newACPActionEnv(t, "default")
	creds := env.credentialsFile()
	permission := func(benign int, last string) acp.Verdict {
		var locations []any
		for i := 0; i < benign; i++ {
			locations = append(locations, map[string]any{"path": filepath.Join(env.project, fmt.Sprintf("f%d.txt", i))})
		}
		if last != "" {
			locations = append(locations, map[string]any{"path": last})
		}
		return env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 1, "session/request_permission", map[string]any{"sessionId": "s", "options": []any{},
			"toolCall": map[string]any{"toolCallId": "t", "kind": "edit", "title": "Edit", "locations": locations}}))
	}
	for _, benign := range []int{0, 7, 8, 20, acpMaxFrameToolCalls - 1, acpMaxFrameToolCalls, acpMaxFrameToolCalls + 40} {
		if verdict := permission(benign, creds); !acpBlocked(verdict.RawAction) {
			t.Errorf("%d workspace locations then the credentials file: %+v, want a block", benign, verdict)
		}
	}
	if verdict := permission(20, ""); verdict.Action != "allow" || verdict.RawAction != "allow" {
		t.Errorf("20 workspace locations: %+v, want a plain allow", verdict)
	}
	over := permission(acpMaxFrameToolCalls+1, "")
	if !acpBlocked(over.RawAction) {
		t.Errorf("%d workspace locations: %+v, want a refusal as unread", acpMaxFrameToolCalls+1, over)
	}
	// A report of the same cannot be refused: it is an alert that would have blocked.
	var locations []any
	for i := 0; i <= acpMaxFrameToolCalls; i++ {
		locations = append(locations, map[string]any{"path": filepath.Join(env.project, fmt.Sprintf("f%d.txt", i))})
	}
	report := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s",
		"update": map[string]any{"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "edit", "locations": locations}}))
	if report.Action != "alert" || !report.WouldBlock {
		t.Errorf("report over the bound: %+v, want an alert that would have blocked", report)
	}
}

// TestACPTerminalWithoutDirectoryRunsInTheSessionDirectory: terminal/create
// names its directory optionally; the editor runs it in the session's, which
// the guard sends. The command is judged there, as the hook of a session in
// that directory judges it (GAP-0297). The pairs are the fixtures' shell
// cases; the parity test checks the project, this the account's home too.
func TestACPTerminalWithoutDirectoryRunsInTheSessionDirectory(t *testing.T) {
	pairs, _ := acpParityPairs(t, loadACPParityCases(t))
	env := newACPActionEnv(t, "default")
	t.Chdir(t.TempDir()) // not the project: the gateway's own directory never decides
	home := filepath.Dir(env.project)
	for _, sessionDir := range []string{env.project, home} {
		env.sessionCWD = sessionDir
		hookEnv := *env
		hookEnv.project = sessionDir
		var compared, mismatches int
		var example string
		for _, pair := range pairs {
			if pair.method != "terminal/create" || pair.noCWD {
				continue
			}
			hook, _ := hookEnv.kiroHook(t, pair.hookTool, pair.hookInput, true)
			acpVerdict := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 1, "terminal/create", map[string]any{"sessionId": "s", "command": pair.hookInput["command"]}))
			compared++
			if normalizeCodexAction(hook) != normalizeCodexAction(acpVerdict.RawAction) {
				mismatches++
				if example == "" {
					example = fmt.Sprintf("%s hook %s / ACP %s", pair.id, hook, acpVerdict.RawAction)
				}
			}
		}
		if compared < 100 || mismatches > 0 {
			t.Errorf("session directory %s: %d terminal pairs, %d differ (e.g. %s)", filepath.Base(sessionDir), compared, mismatches, example)
		}
	}
}

// TestACPTerminalWithNoKnownDirectoryIsRefused: with no directory in the
// frame and none for the session, a command is unknown, never clean. A
// relative directory is joined to the session's. A frame that needs no
// directory (a read or write of an absolute path) is judged as before.
func TestACPTerminalWithNoKnownDirectoryIsRefused(t *testing.T) {
	env := newACPActionEnv(t, "default")
	command := map[string]any{"sessionId": "s", "command": "git", "args": []string{"status"}}
	env.sessionCWD = ""
	refused := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 1, "terminal/create", command))
	// "git status" is benign anywhere: only the missing directory can refuse it.
	if !acpBlocked(refused.RawAction) {
		t.Errorf("terminal with no directory: %+v, want a refusal as unread", refused)
	}
	permission := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 2, "session/request_permission", map[string]any{"sessionId": "s", "options": []any{},
		"toolCall": map[string]any{"toolCallId": "t", "kind": "execute", "rawInput": map[string]any{"command": "git status"}}}))
	if !acpBlocked(permission.RawAction) {
		t.Errorf("execute permission with no directory: %+v, want a refusal", permission)
	}
	report := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
		"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "execute", "rawInput": map[string]any{"command": "git status"}}}))
	if report.Action != "alert" || !report.WouldBlock {
		t.Errorf("execute report with no directory: %+v, want an alert that would have blocked", report)
	}
	read := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 3, "fs/read_text_file", map[string]any{"sessionId": "s", "path": filepath.Join(env.project, "README.md")}))
	if read.Action != "allow" || read.RawAction != "allow" {
		t.Errorf("read of a workspace file with no session directory: %+v, want a plain allow", read)
	}
	if verdict := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 4, "terminal/create", map[string]any{"sessionId": "s", "command": "git", "cwd": env.project})); verdict.Action != "allow" {
		t.Errorf("terminal naming its directory: %+v, want an allow", verdict)
	}
	env.sessionCWD = env.project
	if verdict := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 5, "terminal/create", map[string]any{"sessionId": "s", "command": "git", "cwd": "sub"})); verdict.Action != "allow" {
		t.Errorf("terminal naming a relative directory: %+v, want an allow", verdict)
	}
	if got := acpCallDirectory(env.project, "sub"); got != env.project+string(filepath.Separator)+"sub" {
		t.Errorf("relative directory joined to %q", got)
	}
	if got := acpCallDirectory(env.project, ""); got != env.project {
		t.Errorf("no directory read as %q", got)
	}
}

// TestACPKiroShapedEditInputIsReadAsTheWrite: Kiro's own fs_write and
// str_replace inputs name the text file_text, old_str and new_str. The
// permission and the report of such an edit carry the same text to the rules
// as the Write or Edit the hook judges (review of GAP-0176, P3).
func TestACPKiroShapedEditInputIsReadAsTheWrite(t *testing.T) {
	for _, tc := range []struct {
		name, input, tool string
		want              map[string]string
	}{
		{"create", `{"command":"create","path":"/tmp/x","file_text":"ok"}`, "Write", map[string]string{"file_path": "/tmp/x", "content": "ok"}},
		{"camel case", `{"path":"/tmp/x","fileText":"ok"}`, "Write", map[string]string{"file_path": "/tmp/x", "content": "ok"}},
		{"replace", `{"command":"str_replace","path":"/tmp/x","old_str":"a","new_str":"b"}`, "Edit", map[string]string{"file_path": "/tmp/x", "old_string": "a", "new_string": "b"}},
		{"replace camel case", `{"path":"/tmp/x","oldStr":"a","newStr":"b"}`, "Edit", map[string]string{"file_path": "/tmp/x", "old_string": "a", "new_string": "b"}},
		{"agent-neutral names", `{"path":"/tmp/x","content":"ok"}`, "Write", map[string]string{"file_path": "/tmp/x", "content": "ok"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := json.RawMessage(`{"kind":"edit","title":"Edit","rawInput":` + tc.input + `}`)
			for _, permission := range []bool{true, false} {
				calls, _ := acpToolCallUpdateCalls(raw, "linux", permission)
				if len(calls) != 1 || calls[0].tool != tc.tool {
					t.Fatalf("permission=%v: calls %+v, want one %s call", permission, calls, tc.tool)
				}
				var got map[string]string
				if err := json.Unmarshal(calls[0].args, &got); err != nil || len(got) != len(tc.want) {
					t.Fatalf("permission=%v: args %s, want %v", permission, calls[0].args, tc.want)
				}
				for key, value := range tc.want {
					if got[key] != value {
						t.Errorf("permission=%v: %s = %q, want %q", permission, key, got[key], value)
					}
				}
			}
		})
	}
}
