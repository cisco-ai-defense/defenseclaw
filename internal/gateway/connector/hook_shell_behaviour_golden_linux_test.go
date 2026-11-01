// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestShellHookBehaviourMatchesGolden pins what every connector shell hook
// decides, prints and sends (sandbox-visibility:GAP-0028, issue #1130): for
// each hook, render mode, gateway answer and hook event, and for the
// tool-call corpus (internal/gateway/testdata/security_suite/toolcall), it
// records the exit status, stdout, stderr, hook-failures.jsonl and every
// request the gateway received, and compares one digest per case with the
// golden written from the hooks before their process count was cut. A
// change to a hook's decision, its output or its request fails here.
//
// DC_HOOK_GOLDEN_FULL=1 runs every event, answer and mode and the whole
// corpus (the default runs the tool-call event of each hook in every mode
// and a sample of the rest). DC_HOOK_GOLDEN_UPDATE=1 rewrites the golden
// (with FULL=1, from the hooks whose behaviour it must keep), and
// DC_HOOK_GOLDEN_DUMP=DIR writes each case's normalized observation to DIR,
// so two trees can be compared whole.
func TestShellHookBehaviourMatchesGolden(t *testing.T) {
	for _, tool := range []string{"jq", "curl", "awk"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required: the golden was written with it", tool)
		}
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	if _, err := os.Stat("/etc/defenseclaw/managed-runtime.json"); err == nil {
		t.Skip("a managed computer refuses personal hooks")
	}
	full := os.Getenv("DC_HOOK_GOLDEN_FULL") == "1"
	update := os.Getenv("DC_HOOK_GOLDEN_UPDATE") == "1"
	dump := os.Getenv("DC_HOOK_GOLDEN_DUMP")
	if update && !full {
		t.Fatal("DC_HOOK_GOLDEN_UPDATE=1 needs DC_HOOK_GOLDEN_FULL=1: the golden holds every case")
	}

	// Build the per-user helpers once, from this goroutine.
	scratch := t.TempDir()
	installNativeGatewayForHookTest(t, filepath.Join(scratch, "probe-gw"))
	installNativeHookPostForHookTest(t, filepath.Join(scratch, "probe-post"))

	cases := hookGoldenCases(t, full)
	compare := !update
	if only := os.Getenv("DC_HOOK_GOLDEN_ONLY"); only != "" {
		kept := cases[:0]
		for _, c := range cases {
			if strings.Contains(c.id, only) {
				kept = append(kept, c)
			}
		}
		cases = kept
		update = false
		if _, err := os.Stat(hookGoldenPath); err != nil {
			compare = false
		}
	}
	want := map[string]string{}
	if compare {
		raw, err := os.ReadFile(hookGoldenPath)
		if err != nil {
			t.Fatalf("read %s: %v", hookGoldenPath, err)
		}
		var g hookGoldenFile
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatalf("parse %s: %v", hookGoldenPath, err)
		}
		want = g.Cases
	}
	if dump != "" {
		if err := os.MkdirAll(dump, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	var (
		mu       sync.Mutex
		got      = map[string]string{}
		failures []string
		next     atomic.Int64
		wg       sync.WaitGroup
	)
	workers := 16
	if v, err := strconv.Atoi(os.Getenv("DC_HOOK_GOLDEN_WORKERS")); err == nil && v > 0 {
		workers = v
	}
	base, err := os.MkdirTemp("/tmp", "dcg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(cases) {
					return
				}
				c := cases[i]
				obs, err := runHookGoldenCase(base, i, c)
				mu.Lock()
				if err != nil {
					failures = append(failures, fmt.Sprintf("%s: setup: %v", c.id, err))
					mu.Unlock()
					continue
				}
				digest := obs.digest()
				got[c.id] = digest
				if dump != "" {
					body, _ := json.MarshalIndent(obs, "", "  ")
					_ = os.WriteFile(filepath.Join(dump, strings.ReplaceAll(c.id, "/", "_")+".json"), body, 0o644)
				}
				if compare {
					if w, ok := want[c.id]; !ok {
						failures = append(failures, fmt.Sprintf("%s: no golden digest", c.id))
					} else if w != digest {
						body, _ := json.MarshalIndent(obs, "", "  ")
						failures = append(failures, fmt.Sprintf("%s: digest %s, golden %s; observation:\n%s", c.id, digest, w, body))
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Strings(failures)
	for i, f := range failures {
		if i >= 20 {
			t.Errorf("... and %d more", len(failures)-20)
			break
		}
		t.Error(f)
	}
	if update && len(failures) == 0 {
		body, err := json.MarshalIndent(hookGoldenFile{
			About: "One digest per shell hook case of TestShellHookBehaviourMatchesGolden (hook_shell_behaviour_golden_linux_test.go): " +
				"exit status, stdout, stderr, hook-failures.jsonl and the gateway requests, normalized. Written with " +
				"DC_HOOK_GOLDEN_FULL=1 DC_HOOK_GOLDEN_UPDATE=1 from the hooks whose behaviour it pins (sandbox-visibility:GAP-0028).",
			Cases: got,
		}, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(hookGoldenPath, append(body, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%d shell hook cases (full=%v)", len(cases), full)
}

const hookGoldenPath = "testdata/hook_shell_behaviour.golden.json"

type hookGoldenFile struct {
	About string            `json:"about"`
	Cases map[string]string `json:"cases"`
}

// hookGoldenHook is one shell hook: its connector, script, registered
// arguments for an event, the events it is registered for (the first is
// its tool-call event) and the stdin an agent sends for an event.
type hookGoldenHook struct {
	name    string
	script  string
	conn    func() Connector
	env     []string
	args    func(event string) []string
	events  []string
	payload func(event, command, work string) []byte
}

func hookGoldenJSON(v map[string]interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func hookGoldenHooks() []hookGoldenHook {
	none := func(string) []string { return nil }
	claudeLike := func(event, command, work string) []byte {
		return hookGoldenJSON(map[string]interface{}{
			"session_id": "golden-session", "hook_event_name": event, "cwd": work, "transcript_path": "",
			"permission_mode": "default", "tool_name": "Bash", "tool_input": map[string]interface{}{"command": command},
			"tool_use_id": "toolu_golden", "prompt": command,
		})
	}
	return []hookGoldenHook{
		{name: "claudecode", script: "claude-code-hook.sh", conn: func() Connector { return NewClaudeCodeConnector() }, args: none,
			events:  []string{"PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse", "Stop", "SessionStart", "SubagentStart"},
			payload: claudeLike},
		{name: "claudecode-cursor", script: "claude-code-hook.sh", conn: func() Connector { return NewClaudeCodeConnector() }, args: none,
			events: []string{"PreToolUse"},
			payload: func(event, command, work string) []byte {
				return hookGoldenJSON(map[string]interface{}{"hook_event_name": event, "cursor_version": "2.4.1", "tool_name": "Bash",
					"tool_input": map[string]interface{}{"command": command}, "cwd": work, "session_id": "golden-session"})
			}},
		{name: "codex", script: "codex-hook.sh", conn: func() Connector { return NewCodexConnector() },
			args:   func(e string) []string { return []string{"--event", e, "--hook-contract", "codex-hooks-v4"} },
			events: []string{"PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse", "Stop", "SessionStart", "SessionEnd"},
			payload: func(event, command, work string) []byte {
				return hookGoldenJSON(map[string]interface{}{
					"session_id": "golden-session", "turn_id": "t-golden", "hook_event_name": event, "tool_name": "Bash",
					"tool_input": map[string]interface{}{"command": command}, "tool_use_id": "toolu_golden", "cwd": work,
					"model": "golden", "transcript_path": nil, "permission_mode": "default", "prompt": command,
				})
			}},
		{name: "codex-mismatch", script: "codex-hook.sh", conn: func() Connector { return NewCodexConnector() },
			args:   func(e string) []string { return []string{"--event", "Stop", "--hook-contract", "codex-hooks-v4"} },
			events: []string{"PreToolUse"},
			payload: func(event, command, work string) []byte {
				return hookGoldenJSON(map[string]interface{}{"session_id": "golden-session", "hook_event_name": event, "cwd": work,
					"tool_name": "Bash", "tool_input": map[string]interface{}{"command": command}})
			}},
		{name: "cursor", script: "cursor-hook.sh", conn: func() Connector { return NewCursorConnector() }, args: none,
			events: []string{"beforeShellExecution", "preToolUse", "beforeSubmitPrompt", "stop"},
			payload: func(event, command, work string) []byte {
				return hookGoldenJSON(map[string]interface{}{"hook_event_name": event, "conversation_id": "golden-conv",
					"generation_id": "golden-gen", "command": command, "cwd": work, "tool_name": "Shell",
					"tool_input": map[string]interface{}{"command": command}, "prompt": command, "workspace_roots": []string{work}})
			}},
		{name: "copilot", script: "copilot-hook.sh", conn: func() Connector { return NewCopilotConnector() },
			args:   func(e string) []string { return []string{"--event", e} },
			events: []string{"preToolUse", "permissionRequest", "userPromptSubmitted", "postToolUse", "sessionEnd"},
			payload: func(event, command, work string) []byte {
				args, _ := json.Marshal(map[string]string{"command": command})
				return hookGoldenJSON(map[string]interface{}{"timestamp": 1761955200000, "cwd": work, "toolName": "bash",
					"toolArgs": string(args), "prompt": command, "sessionId": "golden-session"})
			}},
		{name: "devin", script: "devin-hook.sh", conn: func() Connector { return NewDevinConnector() }, args: none,
			events: []string{"PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop"},
			payload: func(event, command, work string) []byte {
				return hookGoldenJSON(map[string]interface{}{"hook_event_name": event, "tool_name": "exec",
					"tool_input": map[string]interface{}{"command": command}, "prompt": command, "session_id": "golden-session", "cwd": work})
			}},
		{name: "kiro", script: "kiro-hook.sh", conn: func() Connector { return NewKiroConnector() },
			args:   func(string) []string { return []string{"--hook-surface", "v3"} },
			events: []string{"preToolUse", "postToolUse", "userPromptSubmit", "stop"},
			payload: func(event, command, work string) []byte {
				return hookGoldenJSON(map[string]interface{}{"hook_event_name": event, "cwd": work, "tool_name": "execute_bash",
					"tool_input": map[string]interface{}{"command": command}, "prompt": command, "session_id": "golden-session"})
			}},
		{name: "hermes", script: "hermes-hook.sh", conn: func() Connector { return NewHermesConnector() }, args: none,
			events: []string{"pre_tool_call", "post_tool_call", "pre_llm_call", "on_session_end"},
			payload: func(event, command, work string) []byte {
				return hookGoldenJSON(map[string]interface{}{"hook_event_name": event, "tool_name": "terminal",
					"tool_input": map[string]interface{}{"command": command}, "session_id": "golden-session", "cwd": work,
					"user_message": command})
			}},
		{name: "antigravity", script: "antigravity-hook.sh", conn: func() Connector { return NewAntigravityConnector() },
			args:   func(e string) []string { return []string{e} },
			events: []string{"PreToolUse", "PostToolUse", "PreInvocation", "Stop"},
			payload: func(event, command, work string) []byte {
				return hookGoldenJSON(map[string]interface{}{"toolName": "run_command",
					"toolInput": map[string]interface{}{"CommandLine": command}, "cwd": work, "conversationId": "golden-session"})
			}},
		{name: "inspect-tool", script: "inspect-tool.sh", conn: func() Connector { return NewClaudeCodeConnector() }, args: none,
			env: []string{"CLAUDE_TOOL_NAME=Bash"}, events: []string{"tool"},
			payload: func(_, command, _ string) []byte {
				return hookGoldenJSON(map[string]interface{}{"command": command})
			}},
		{name: "inspect-request", script: "inspect-request.sh", conn: func() Connector { return NewClaudeCodeConnector() }, args: none,
			events:  []string{"request"},
			payload: func(_, command, _ string) []byte { return []byte(command) }},
	}
}

// hookGoldenMode is one render of the hooks: per-user with the config's
// outage tier, or a standalone managed render on its hook socket.
type hookGoldenMode struct {
	name     string
	managed  bool
	failMode string
	config   string
	env      []string
}

func hookGoldenModes() []hookGoldenMode {
	return []hookGoldenMode{
		{name: "user-default-open", failMode: "open", config: outageDefaultTierConfig},
		{name: "user-default-closed", failMode: "closed", config: outageDefaultTierConfig},
		{name: "user-strict-tier", failMode: "open", config: outageStrictTierConfig},
		{name: "user-strict-availability", failMode: "open", config: outageDefaultTierConfig, env: []string{"DEFENSECLAW_STRICT_AVAILABILITY=1"}},
		{name: "user-no-config", failMode: "open"},
		{name: "managed-closed", managed: true, failMode: "closed"},
		{name: "managed-open", managed: true, failMode: "open"},
	}
}

// hookGoldenAnswer is what the fake gateway answers: status and body per
// request (n counts from 1), or no gateway at all.
type hookGoldenAnswer struct {
	name        string
	unreachable bool
	answer      func(n int, event string) (int, string)
}

func hookGoldenFixed(status int, body string) func(int, string) (int, string) {
	return func(int, string) (int, string) { return status, body }
}

func hookGoldenNative(event, decision, reason string) map[string]interface{} {
	return map[string]interface{}{
		"hookSpecificOutput": map[string]interface{}{"hookEventName": event, "permissionDecision": decision, "permissionDecisionReason": reason},
		"decision":           map[string]string{"deny": "block", "ask": "ask", "allow": "approve"}[decision],
		"reason":             reason, "continue": decision != "deny", "stopReason": reason,
	}
}

func hookGoldenHookOutput(decision, reason string) map[string]interface{} {
	block := map[string]string{"deny": "block", "ask": "ask", "allow": "allow"}[decision]
	return map[string]interface{}{"decision": block, "reason": reason, "permission": decision, "permissionDecision": decision,
		"permissionDecisionReason": reason, "behavior": decision, "user_message": reason, "agent_message": reason,
		"continue": decision != "deny"}
}

func hookGoldenAnswers() []hookGoldenAnswer {
	decided := func(action, decision, reason string) func(int, string) (int, string) {
		return func(_ int, event string) (int, string) {
			body := map[string]interface{}{"action": action, "reason": reason,
				"claude_code_output": hookGoldenNative(event, decision, reason),
				"codex_output":       hookGoldenNative(event, decision, reason),
				"hook_output":        hookGoldenHookOutput(decision, reason)}
			return 200, string(hookGoldenJSON(body))
		}
	}
	return []hookGoldenAnswer{
		{name: "allow", answer: hookGoldenFixed(200, `{"action":"allow"}`)},
		{name: "allow-output", answer: decided("allow", "allow", "golden allow")},
		{name: "alert", answer: hookGoldenFixed(200, `{"action":"alert","reason":"golden alert","would_block":false,"hook_output":{"decision":"allow"}}`)},
		{name: "block-output", answer: decided("block", "deny", "golden block: SEC-GOLDEN")},
		{name: "block-bare", answer: hookGoldenFixed(200, `{"action":"block","reason":"golden bare block"}`)},
		{name: "block-no-reason", answer: hookGoldenFixed(200, `{"action":"block"}`)},
		{name: "confirm-output", answer: decided("confirm", "ask", "golden confirm")},
		{name: "confirm-bare", answer: hookGoldenFixed(200, `{"action":"confirm","reason":"golden bare confirm"}`)},
		{name: "block-contradicted", answer: decided("block", "allow", "golden contradicted")},
		{name: "unknown-action", answer: hookGoldenFixed(200, `{"action":"maybe","hook_output":{"decision":"allow"}}`)},
		{name: "no-action", answer: hookGoldenFixed(200, `{"reason":"no action"}`)},
		{name: "action-newline", answer: hookGoldenFixed(200, `{"action":"block\n","reason":"golden newline"}`)},
		{name: "action-number", answer: hookGoldenFixed(200, `{"action":7}`)},
		{name: "truncated-json", answer: hookGoldenFixed(200, `{"action":`)},
		{name: "duplicate-keys", answer: hookGoldenFixed(200, `{"action":"allow","action":"block"}`)},
		{name: "not-an-object", answer: hookGoldenFixed(200, `["allow"]`)},
		{name: "nul-byte", answer: hookGoldenFixed(200, "{\"action\":\"al\x00low\"}")},
		{name: "trailing-newlines", answer: hookGoldenFixed(200, "{\"action\":\"allow\",\"hook_output\":{}}\n\n\n")},
		{name: "spaced", answer: hookGoldenFixed(200, "  {\n \"action\" : \"allow\" ,\n \"codex_output\" : null }  ")},
		{name: "empty-body", answer: hookGoldenFixed(200, "")},
		{name: "http-500", answer: hookGoldenFixed(500, `{"error":"golden boom"}`)},
		{name: "http-401", answer: hookGoldenFixed(401, `{"error":"unauthorized"}`)},
		{name: "http-403", answer: hookGoldenFixed(403, `{"error":"forbidden","message":"golden policy refusal"}`)},
		{name: "http-429-then-allow", answer: func(n int, _ string) (int, string) {
			if n == 1 {
				return 429, `{"error":"busy","retry_after_seconds":1}`
			}
			return 200, `{"action":"allow"}`
		}},
		{name: "unreachable", unreachable: true},
	}
}

type hookGoldenCase struct {
	id      string
	hook    hookGoldenHook
	mode    hookGoldenMode
	answer  hookGoldenAnswer
	event   string
	stdin   []byte
	env     []string
	command string
}

func hookGoldenCorpus(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "testdata", "security_suite", "toolcall", "corpus.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		var row struct {
			Command string `json:"command"`
		}
		if json.Unmarshal([]byte(line), &row) == nil && row.Command != "" {
			out = append(out, row.Command)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) < 100 {
		t.Fatalf("tool-call corpus has %d commands", len(out))
	}
	return out
}

func hookGoldenCases(t *testing.T, full bool) []hookGoldenCase {
	t.Helper()
	var cases []hookGoldenCase
	add := func(c hookGoldenCase) {
		c.id = fmt.Sprintf("%s/%s/%s/%s", c.hook.name, c.mode.name, c.event, c.answer.name) + c.id
		cases = append(cases, c)
	}
	const command = "cat ./hello.txt"
	answers := hookGoldenAnswers()
	modes := hookGoldenModes()
	byName := map[string]hookGoldenAnswer{}
	for _, a := range answers {
		byName[a.name] = a
	}
	for _, h := range hookGoldenHooks() {
		for ei, event := range h.events {
			for _, m := range modes {
				for _, a := range answers {
					// Every answer in every mode for the tool-call event; the
					// other events in full runs, and with the main answers.
					main := a.name == "allow" || a.name == "block-output" || a.name == "block-bare" || a.name == "http-500" || a.name == "unreachable"
					if ei > 0 && !full && !(main && (m.name == "user-default-open" || m.name == "managed-closed")) {
						continue
					}
					if a.unreachable && !full && ei == 0 && m.name != "user-default-open" && m.name != "user-default-closed" &&
						m.name != "user-strict-availability" && m.name != "managed-closed" {
						continue
					}
					add(hookGoldenCase{hook: h, mode: m, answer: a, event: event, command: command})
				}
			}
		}
		event := h.events[0]
		// Agent environment and stdin edge cases.
		envs := map[string][]string{
			"trace":     {"TRACEPARENT=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "TRACESTATE=dc=golden"},
			"bad-trace": {"DEFENSECLAW_TRACEPARENT=00-zz-00f067aa0ba902b7-01", "OTEL_TRACESTATE=bad state\x01"},
			"home-set":  {"DEFENSECLAW_HOME=/nonexistent/golden"},
			"no-ssh":    {"SSH_CONNECTION=", "SSH_TTY=", "XDG_SESSION_ID="},
		}
		for _, name := range []string{"trace", "bad-trace", "home-set", "no-ssh"} {
			for _, m := range []hookGoldenMode{modes[0], modes[5]} {
				add(hookGoldenCase{id: "/env-" + name, hook: h, mode: m, answer: byName["allow"], event: event, command: command, env: envs[name]})
			}
		}
		big := strings.Repeat("A", 950*1024)
		huge := strings.Repeat("B", 1100*1024)
		stdins := map[string][]byte{
			"empty":          {},
			"not-json":       []byte("not json at all\n"),
			"nul":            append(h.payload(event, command, "<WORK>"), 0, '{', '}'),
			"trailing-nl":    append(h.payload(event, command, "<WORK>"), '\n', '\n'),
			"nested-event":   []byte(`{"tool_input":{"hook_event_name":"PreToolUse"},"hook_event_name":"Stop"}`),
			"over-transport": h.payload(event, big, "<WORK>"),
			"over-cap":       h.payload(event, huge, "<WORK>"),
		}
		for _, name := range []string{"empty", "not-json", "nul", "trailing-nl", "nested-event", "over-transport", "over-cap"} {
			for _, m := range []hookGoldenMode{modes[0], modes[1], modes[5]} {
				for _, a := range []string{"allow", "block-output"} {
					add(hookGoldenCase{id: "/stdin-" + name, hook: h, mode: m, answer: byName[a], event: event, stdin: stdins[name]})
				}
			}
		}
	}
	rotate := []string{"allow", "allow-output", "block-output", "block-bare", "confirm-output", "alert"}
	corpus := hookGoldenCorpus(t)
	for _, h := range hookGoldenHooks() {
		for i, cmd := range corpus {
			if !full && i%25 != 0 {
				continue
			}
			add(hookGoldenCase{id: fmt.Sprintf("/corpus-%03d", i), hook: h, mode: hookGoldenModes()[0],
				answer: byName[rotate[i%len(rotate)]], event: h.events[0], command: cmd})
		}
	}
	return cases
}

// hookGoldenRequest is one request the fake gateway received.
type hookGoldenRequest struct {
	Method string              `json:"method"`
	Path   string              `json:"path"`
	Header map[string][]string `json:"header"`
	Body   string              `json:"body"`
}

type hookGoldenObservation struct {
	Exit     int                 `json:"exit"`
	Stdout   string              `json:"stdout"`
	Stderr   string              `json:"stderr"`
	Failures []string            `json:"hook_failures"`
	Requests []hookGoldenRequest `json:"requests"`
}

func (o hookGoldenObservation) digest() string {
	body, err := json.Marshal(o)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])[:20]
}

type hookGoldenGateway struct {
	mu       sync.Mutex
	answer   func(n int, event string) (int, string)
	requests []hookGoldenRequest
}

func (g *hookGoldenGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	event := r.Header.Get("X-DefenseClaw-Hook-Event")
	if event == "" {
		event = r.Header.Get("X-DefenseClaw-Antigravity-Event")
	}
	var payload struct {
		Event string `json:"hook_event_name"`
	}
	if event == "" && json.Unmarshal(body, &payload) == nil {
		event = payload.Event
	}
	if event == "" {
		event = "PreToolUse"
	}
	header := map[string][]string{}
	for k, v := range r.Header {
		header[k] = append([]string(nil), v...)
	}
	g.mu.Lock()
	g.requests = append(g.requests, hookGoldenRequest{Method: r.Method, Path: r.URL.RequestURI(), Header: header, Body: string(body)})
	n := len(g.requests)
	g.mu.Unlock()
	status, answer := g.answer(n, event)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, answer)
}

var hookGoldenRenderMu sync.Mutex

func runHookGoldenCase(base string, i int, c hookGoldenCase) (hookGoldenObservation, error) {
	var obs hookGoldenObservation
	root := filepath.Join(base, strconv.Itoa(i))
	home := filepath.Join(root, "home")
	dataDir := filepath.Join(home, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	work := filepath.Join(root, "work")
	defer os.RemoveAll(root)
	for _, dir := range []string{root, home, work, filepath.Join(home, ".local", "bin")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return obs, err
		}
	}
	if err := os.WriteFile(filepath.Join(work, "hello.txt"), []byte("hello\n"), 0o600); err != nil {
		return obs, err
	}
	gateway := &hookGoldenGateway{answer: c.answer.answer}
	server := &http.Server{Handler: gateway, ReadHeaderTimeout: 10 * time.Second}
	var listener net.Listener
	var err error
	socket := ""
	if c.mode.managed {
		socket = filepath.Join(root, "run", "hook.sock")
		if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil {
			return obs, err
		}
		for _, dir := range []string{root, filepath.Dir(socket)} {
			if err := os.Chmod(dir, 0o755); err != nil {
				return obs, err
			}
		}
		if !c.answer.unreachable {
			if listener, err = net.Listen("unix", socket); err != nil {
				return obs, err
			}
		}
	} else if !c.answer.unreachable {
		if listener, err = net.Listen("tcp4", "127.0.0.1:0"); err != nil {
			return obs, err
		}
	}
	addr := ""
	if listener != nil {
		go func() { _ = server.Serve(listener) }()
		defer server.Close()
		if !c.mode.managed {
			addr = listener.Addr().String()
		}
	}
	if addr == "" {
		// A port nothing listens on, held for the case: bound but not
		// listening, it refuses every connection, and no other case's
		// gateway can be given it.
		port, closeHeld, err := hookGoldenRefusingPort()
		if err != nil {
			return obs, err
		}
		defer closeHeld()
		addr = "127.0.0.1:" + strconv.Itoa(port)
	}
	if !c.mode.managed {
		if err := os.Link(nativeGatewayForHookTests.path, filepath.Join(home, ".local", "bin", "defenseclaw-gateway")); err != nil {
			return obs, err
		}
		if err := os.Link(nativeHookPostForHookTests.path, filepath.Join(home, ".local", "bin", "defenseclaw-hook-post")); err != nil {
			return obs, err
		}
		if c.mode.config != "" {
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				return obs, err
			}
			if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(c.mode.config), 0o600); err != nil {
				return obs, err
			}
		}
	}
	opts := SetupOpts{DataDir: dataDir, APIAddr: addr, APIToken: "golden-gateway-token",
		HookAPIToken: "golden-scoped-token", HookAPITokenScoped: true, HookFailMode: c.mode.failMode}
	if c.mode.managed {
		opts.ManagedEnterprise = true
		opts.ManagedHookSocket = socket
		opts.ManagedServiceUID = os.Getuid()
	}
	hookGoldenRenderMu.Lock()
	err = WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c.hook.conn())
	hookGoldenRenderMu.Unlock()
	if err != nil {
		return obs, err
	}
	script := filepath.Join(hookDir, c.hook.script)
	if dir := os.Getenv("DC_HOOK_GOLDEN_SCRIPTS"); dir != "" {
		// The rendered hooks of each mode, for bash -n and shellcheck.
		target := filepath.Join(dir, c.mode.name)
		if err := os.MkdirAll(target, 0o755); err != nil {
			return obs, err
		}
		names, _ := filepath.Glob(filepath.Join(hookDir, "*.sh"))
		for _, name := range names {
			if body, err := os.ReadFile(name); err == nil {
				_ = os.WriteFile(filepath.Join(target, filepath.Base(name)), body, 0o644)
			}
		}
	}
	if c.mode.managed {
		curl, err := exec.LookPath("curl")
		if err != nil {
			return obs, err
		}
		helper := filepath.Join(hookDir, "_hardening.sh")
		b, err := os.ReadFile(helper)
		if err != nil {
			return obs, err
		}
		baked := strings.Replace(string(b), `DEFENSECLAW_BAKED_HOOK_PATH=""`,
			"DEFENSECLAW_BAKED_HOOK_PATH="+shellSingleQuoteForTest(filepath.Dir(curl)+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"), 1)
		if err := os.WriteFile(helper, []byte(baked), 0o644); err != nil {
			return obs, err
		}
	}
	stdin := c.stdin
	if stdin == nil {
		stdin = c.hook.payload(c.event, c.command, work)
	} else {
		stdin = bytes.ReplaceAll(stdin, []byte("<WORK>"), []byte(work))
	}
	env := []string{}
	for _, kv := range sanitizedTestEnv() {
		key := kv[:strings.IndexByte(kv+"=", '=')]
		switch {
		case strings.HasPrefix(key, "SSH_"), strings.HasPrefix(key, "OTEL_"), key == "XDG_SESSION_ID", key == "KRB5CCNAME",
			key == "TRACEPARENT", key == "TRACESTATE", key == "HOME", key == "CDPATH", key == "BASH_ENV", key == "ENV":
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "HOME="+home, "SSH_CONNECTION=10.0.0.1 50000 10.0.0.2 22", "SSH_TTY=/dev/pts/9", "XDG_SESSION_ID=7",
		"KRB5CCNAME=FILE:"+filepath.Join(root, "no-krb5cc"))
	env = append(env, c.mode.env...)
	env = append(env, c.hook.env...)
	env = append(env, c.env...)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, script, c.hook.args(c.event)...)
	cmd.Dir = work
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	obs.Exit = 0
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		obs.Exit = exitErr.ExitCode()
	} else if runErr != nil {
		return obs, runErr
	}
	norm := hookGoldenNormalizer(root, addr, socket, work)
	obs.Stdout = norm(stdout.String())
	obs.Stderr = norm(stderr.String())
	if raw, err := os.ReadFile(filepath.Join(dataDir, "logs", "hook-failures.jsonl")); err == nil {
		for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
			obs.Failures = append(obs.Failures, norm(hookGoldenStripClock(line)))
		}
	}
	gateway.mu.Lock()
	for _, r := range gateway.requests {
		// No hook sends a GET: one here is another program's health probe
		// that reached this case's loopback port after its own gateway
		// left it.
		if r.Method == http.MethodGet && r.Path == "/health" {
			continue
		}
		header := map[string][]string{}
		for k, v := range r.Header {
			for _, value := range v {
				// The answer budget the hook has left when it sends: it grows as
				// the hook gets faster, so only its presence is pinned.
				if k == "X-Defenseclaw-Hook-Answer-Within-Ms" {
					value = "<MS>"
				}
				// The body carries this case's folder, whose name varies in
				// length: pin that the length is the body's.
				if k == "Content-Length" {
					if value == strconv.Itoa(len(r.Body)) {
						value = "<BODY-LENGTH>"
					} else {
						value = "mismatch:" + value
					}
				}
				header[k] = append(header[k], norm(value))
			}
		}
		obs.Requests = append(obs.Requests, hookGoldenRequest{Method: r.Method, Path: r.Path, Header: header, Body: norm(r.Body)})
	}
	gateway.mu.Unlock()
	return obs, nil
}

// hookGoldenRefusingPort binds a loopback TCP port without listening on it.
func hookGoldenRefusingPort() (int, func(), error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		_ = syscall.Close(fd)
		return 0, nil, err
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		_ = syscall.Close(fd)
		return 0, nil, err
	}
	in4, ok := sa.(*syscall.SockaddrInet4)
	if !ok {
		_ = syscall.Close(fd)
		return 0, nil, fmt.Errorf("unexpected socket address %T", sa)
	}
	return in4.Port, func() { _ = syscall.Close(fd) }, nil
}

var (
	hookGoldenCallID   = regexp.MustCompile(`(\\?"call_id\\?":\\?")[0-9]+-[0-9]+`)
	hookGoldenClockKey = regexp.MustCompile(`"(ts|time|timestamp|at|elapsed_ms|duration_ms)":("[^"]*"|[0-9.]+)`)
	hookGoldenHookTmp  = regexp.MustCompile(`[^\s"':]*defenseclaw-hook\.[A-Za-z0-9]{8}`)
	hookGoldenKrb      = regexp.MustCompile(`;(krb|cc)=[^;\s"]*`)
)

func hookGoldenStripClock(line string) string {
	// call_id is the hook's pid and $RANDOM.
	line = hookGoldenCallID.ReplaceAllString(line, "${1}<CALL>")
	return hookGoldenClockKey.ReplaceAllString(line, `"$1":"<CLOCK>"`)
}

func hookGoldenNormalizer(root, addr, socket, work string) func(string) string {
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	uid := strconv.Itoa(os.Getuid())
	return func(s string) string {
		s = hookGoldenHookTmp.ReplaceAllString(s, "<HOOKTMP>")
		if socket != "" {
			s = strings.ReplaceAll(s, socket, "<SOCKET>")
		}
		s = strings.ReplaceAll(s, work, "<WORK>")
		s = strings.ReplaceAll(s, root, "<ROOT>")
		s = strings.ReplaceAll(s, addr, "<ADDR>")
		if name != "" {
			s = strings.ReplaceAll(s, "User-Name: "+name, "User-Name: <USER>")
			if strings.Contains(s, "User-Name") || len(s) < len(name)+4 {
				s = strings.ReplaceAll(s, name, "<USER>")
			}
		}
		if s == uid {
			s = "<UID>"
		}
		return hookGoldenKrb.ReplaceAllString(s, ";$1=<KRB>")
	}
}
