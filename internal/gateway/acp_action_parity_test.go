// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-10:GAP-0176 parity: the same action through the Kiro hook and
// through the Kiro ACP guard gets the same verdict and the same rule ids, in
// every pack.
//
// The cases are not written here. testdata/acp_parity_cases.jsonl holds, by
// case id, the tool calls of two existing S7 corpora: gap-regression (every
// shell, Write and Edit case) and win-credential-paths (a stride sample of
// its Write and Edit cases). Each case is converted to the Kiro hook call
// and to the ACP frame that performs the same action:
//
//	shell (Bash, PowerShell, terminal)  execute_bash / execute_pwsh   terminal/create
//	Write                               fs_write {path, content}      fs/write_text_file
//	Edit                                str_replace                   session/request_permission (kind edit)
//	(the path of a Write or Edit)       fs_read {path}                fs/read_text_file
//
// Cases of other tools (apply_patch) have no ACP frame and are left out.
type acpParityCase struct {
	ID     string          `json:"id"`
	Corpus string          `json:"corpus"`
	Tool   string          `json:"tool"`
	Args   json.RawMessage `json:"args"`
}

type acpParityPair struct {
	id        string
	hookTool  string
	hookInput map[string]any
	method    string
	params    map[string]any
	id0       int // JSON-RPC id of the frame; 0 for a notification
}

func loadACPParityCases(t *testing.T) []acpParityCase {
	t.Helper()
	file, err := os.Open("testdata/acp_parity_cases.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var cases []acpParityCase
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 16<<20)
	for scanner.Scan() {
		var c acpParityCase
		if err := json.Unmarshal(scanner.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, c)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return cases
}

func acpParityPairs(t *testing.T, cases []acpParityCase) (pairs []acpParityPair, skipped int) {
	t.Helper()
	seenRead := map[string]bool{}
	read := func(id, path string) {
		if path == "" || seenRead[path] {
			return
		}
		seenRead[path] = true
		pairs = append(pairs, acpParityPair{
			id: id + "/read", hookTool: "fs_read", hookInput: map[string]any{"path": path},
			method: "fs/read_text_file", params: map[string]any{"sessionId": "s", "path": path}, id0: 1,
		})
	}
	for _, c := range cases {
		var args map[string]any
		if json.Unmarshal(c.Args, &args) != nil {
			skipped++
			continue
		}
		str := func(key string) (string, bool) { value, ok := args[key].(string); return value, ok }
		switch strings.ToLower(c.Tool) {
		case "bash", "powershell", "terminal", "shell":
			command, ok := str("command")
			if !ok || strings.TrimSpace(command) == "" {
				skipped++
				continue
			}
			// terminal/create is judged for the editor's platform: PowerShell on
			// a Windows gateway. The hook call that performs the same action
			// there is Kiro's PowerShell tool, whatever shell the corpus case
			// was written for.
			hookTool := "execute_bash"
			if strings.EqualFold(c.Tool, "powershell") || runtime.GOOS == "windows" {
				hookTool = "execute_pwsh"
			}
			pairs = append(pairs, acpParityPair{
				id: c.ID, hookTool: hookTool, hookInput: map[string]any{"command": command},
				method: "terminal/create", params: map[string]any{"sessionId": "s", "command": command}, id0: 1,
			})
		case "write":
			path, ok1 := str("file_path")
			content, ok2 := str("content")
			if !ok1 || !ok2 {
				skipped++
				continue
			}
			pairs = append(pairs, acpParityPair{
				id: c.ID, hookTool: "fs_write", hookInput: map[string]any{"path": path, "content": content},
				method: "fs/write_text_file", params: map[string]any{"sessionId": "s", "path": path, "content": content}, id0: 1,
			})
			read(c.ID, path)
		case "edit":
			path, ok1 := str("file_path")
			oldText, ok2 := str("old_string")
			newText, ok3 := str("new_string")
			if !ok1 || !ok2 || !ok3 {
				skipped++
				continue
			}
			pairs = append(pairs, acpParityPair{
				id: c.ID, hookTool: "str_replace", hookInput: map[string]any{"path": path, "oldStr": oldText, "newStr": newText},
				method: "session/request_permission", id0: 1,
				params: map[string]any{"sessionId": "s", "options": []any{}, "toolCall": map[string]any{
					"toolCallId": "t", "kind": "edit", "title": "Edit", "locations": []any{map[string]any{"path": path}},
					"rawInput": map[string]any{"file_path": path, "old_string": oldText, "new_string": newText},
				}},
			})
			read(c.ID, path)
		default:
			skipped++
		}
	}
	return pairs, skipped
}

// kiroHook sends one Kiro preToolUse call to the hook handler.
//
// withCWD sends the session working directory the way a Kiro hook does. An
// ACP fs or permission frame names no working directory (terminal/create
// does), so those pairs are sent without one: both surfaces then judge the
// same operands in the same directory.
func (e *acpActionEnv) kiroHook(t *testing.T, tool string, input map[string]any, withCWD bool) (rawAction string, ruleIDs []string) {
	t.Helper()
	payload := map[string]any{"hook_event_name": "preToolUse", "session_id": "s", "tool_name": tool, "tool_input": input}
	if withCWD {
		payload["cwd"] = e.project
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/kiro/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
	recorder := httptest.NewRecorder()
	e.hookAPI.handleAgentHook("kiro").ServeHTTP(recorder, req)
	var resp struct {
		RawAction string   `json:"raw_action"`
		Findings  []string `json:"findings"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("hook answer is not JSON (status %d)", recorder.Code)
	}
	// The answer's rule_ids are filled in by the audit emit, which this
	// handler runs without; its findings are "RULE:title" (a CodeGuard
	// finding "codeguard:RULE:title").
	for _, finding := range resp.Findings {
		finding = strings.TrimPrefix(finding, "codeguard:")
		id, _, _ := strings.Cut(finding, ":")
		if !slices.Contains(ruleIDs, id) {
			ruleIDs = append(ruleIDs, id)
		}
	}
	return resp.RawAction, ruleIDs
}

func acpVerdictRuleIDs(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, _ := body["defenseclaw.guardrail.rule_ids"].([]any)
	ids := make([]string, 0, len(raw))
	for _, id := range raw {
		if text, ok := id.(string); ok {
			ids = append(ids, text)
		}
	}
	return ids
}

func TestACPActionParityWithKiroHook(t *testing.T) {
	cases := loadACPParityCases(t)
	pairs, skipped := acpParityPairs(t, cases)
	if len(pairs) < 200 {
		t.Fatalf("only %d pairs from %d cases", len(pairs), len(cases))
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			env := newACPActionEnv(t, pack)
			type hookResult struct {
				raw string
				ids []string
			}
			hooks := make([]hookResult, len(pairs))
			acpRaw := make([]string, len(pairs))
			for i, pair := range pairs {
				hooks[i].raw, hooks[i].ids = env.kiroHook(t, pair.hookTool, pair.hookInput, pair.method == "terminal/create")
				params := pair.params
				if pair.method == "terminal/create" {
					// The hook payload names the session's working directory;
					// terminal/create names the command's.
					params = map[string]any{"sessionId": "s", "command": pair.params["command"], "cwd": env.project}
				}
				frame := acpFrameJSON(t, pair.id0, pair.method, params)
				acpRaw[i] = env.evaluate(t, acp.AgentToClient, frame).RawAction
			}
			events := readStoredGuardrailEventsV8(t, env.capture.store.DatabasePath())
			if len(events) != len(pairs) {
				t.Fatalf("%d guardrail events for %d ACP frames", len(events), len(pairs))
			}
			mismatches, flagged, aliased := 0, 0, 0
			classes := map[string][]string{}
			for i, pair := range pairs {
				ids := acpVerdictRuleIDs(t, events[i].Body)
				want, got := slices.Clone(hooks[i].ids), slices.Clone(ids)
				slices.Sort(want)
				slices.Sort(got)
				if !slices.Equal(want, got) && slices.Equal(canonicalPathRuleIDs(want), canonicalPathRuleIDs(got)) {
					// The same credential file under its Windows spelling: Kiro's own
					// fs_write label reads a C:\ path with the PATH-WIN-* twin of the
					// rule the normalized Write reads it with. The action is equal.
					aliased++
					got = want
				}
				hookAction, acpAction := normalizeCodexAction(hooks[i].raw), normalizeCodexAction(acpRaw[i])
				if hookAction != "allow" || len(want) > 0 {
					flagged++
				}
				if hookAction != acpAction || !slices.Equal(want, got) {
					mismatches++
					class := fmt.Sprintf("hook %s %v / ACP %s %v", hookAction, want, acpAction, got)
					classes[class] = append(classes[class], pair.id)
				}
			}
			for class, ids := range classes {
				t.Errorf("%d pairs: %s (e.g. %s)", len(ids), class, ids[0])
			}
			t.Logf("%s: %d cases -> %d pairs (%d cases without an ACP frame), %d flagged by the hook, %d with the PATH-WIN-* twin of the same rule, %d mismatches",
				pack, len(cases), len(pairs), skipped, flagged, aliased, mismatches)
			if mismatches > 0 {
				t.Errorf("%d of %d pairs differ", mismatches, len(pairs))
			}
		})
	}
}

// canonicalPathRuleIDs names each PATH-WIN-* rule by its PATH-* twin.
func canonicalPathRuleIDs(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = strings.Replace(id, "PATH-WIN-", "PATH-", 1)
	}
	slices.Sort(out)
	return out
}
