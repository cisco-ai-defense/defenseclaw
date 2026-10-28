// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

const stopEventNotBlockedLead = "DefenseClaw is not blocking the "

// The shell hooks use the native runner's stop set (#1140); OpenCode's
// stop events reach only the native runner (its plugin calls the binary).
func TestShellFailedStopEventMatchesTheNativeStopSet(t *testing.T) {
	type probe struct{ connector, event, payload, env string }
	var stops, others []probe
	for _, connector := range []string{"claudecode", "codex", "copilot", "cursor", "devin", "kiro"} {
		events := hookexec.NeutralLifecycleEvents(connector)
		if len(events) == 0 {
			t.Fatalf("%s has no native stop set", connector)
		}
		for _, event := range events {
			stops = append(stops, probe{connector: connector, event: event})
			stops = append(stops, probe{connector: connector, payload: `{"hook_event_name":"` + event + `"}`})
			// The Secure Client profile keeps its results.
			others = append(others, probe{connector: connector, event: event, env: "_DC_SECURE_CLIENT_HOOK=1"})
		}
	}
	stops = append(stops, probe{connector: "cursor", event: "SESSIONEND"}, probe{connector: "devin", payload: `{"event":"Stop"}`},
		// A null event field is absent, as for the native runner.
		probe{connector: "claudecode", payload: `{"hook_event_name":"Stop","event":null}`},
		probe{connector: "devin", payload: `{"hook_event_name":null,"event":"Stop"}`})
	others = append(others,
		probe{connector: "codex", event: "PreToolUse"}, probe{connector: "codex", event: "stop"},
		probe{connector: "claudecode", event: "UserPromptSubmit"}, probe{connector: "kiro", event: "PostToolUse"},
		probe{connector: "cursor", event: "beforeShellExecution"}, probe{connector: "copilot", event: "preToolUse"},
		probe{connector: "opencode", event: "session.idle"}, probe{connector: "hermes", event: "on_session_end"},
		probe{connector: "amp", event: "Stop"}, probe{connector: "claudecode"},
		probe{connector: "claudecode", payload: `{}`}, probe{connector: "claudecode", payload: `not json`},
		probe{connector: "devin", payload: `{"hook_event_name":"Stop","event":"PreToolUse"}`},
	)
	for _, m := range malformedStopEventProbes() {
		others = append(others, probe(m))
	}
	check := func(p probe, want bool) {
		t.Helper()
		cmd := exec.Command("bash", "-c", `set -euo pipefail; . "$1"; defenseclaw_failed_stop_event "$2" "$3" "$4"`,
			"probe", filepath.Join("hooks", "_hardening.sh"), p.connector, p.event, p.payload)
		cmd.Env = append(sanitizedTestEnv(), p.env)
		err := cmd.Run()
		if got := err == nil; got != want {
			t.Errorf("%+v: stop event = %v, want %v (%v)", p, got, want, err)
		}
	}
	for _, p := range stops {
		check(p, true)
	}
	for _, p := range others {
		check(p, false)
	}
}

// malformedStopEventProbes are payloads that name no stop event: an event
// field that is not a string (the native runner fails to decode it), two
// stop events that disagree, more than one JSON value or not an object.
func malformedStopEventProbes() []struct{ connector, event, payload, env string } {
	var out []struct{ connector, event, payload, env string }
	for _, payload := range []string{
		`{"hook_event_name":"Stop","event":false}`,
		`{"hook_event_name":false,"event":"Stop"}`,
		`{"hook_event_name":"Stop","event":true}`,
		`{"hook_event_name":"Stop","event":0}`,
		`{"hook_event_name":"Stop","event":{}}`,
		`{"hook_event_name":"Stop","event":["Stop"]}`,
		`{"hook_event_name":["Stop"]}`,
		`{"hook_event_name":"SubagentStop","event":"Stop"}`,
		`{"hook_event_name":"Stop"} {}`,
		`[{"hook_event_name":"Stop"}]`,
		`"Stop"`,
	} {
		out = append(out, struct{ connector, event, payload, env string }{connector: "claudecode", payload: payload})
		out = append(out, struct{ connector, event, payload, env string }{connector: "devin", payload: payload})
	}
	return out
}

// The stop exception reads the payload's event fields the same way with jq,
// with python3 only and with neither (the string scanner): a malformed event
// identity never names a stop event (#1140 review).
func TestShellFailedStopEventFieldTypesWithoutJQ(t *testing.T) {
	tools := func(names ...string) string {
		dir := t.TempDir()
		for _, name := range names {
			path, err := exec.LookPath(name)
			if err != nil {
				t.Skipf("%s not found: %v", name, err)
			}
			if err := os.Symlink(path, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	backends := map[string]string{
		"python3": tools("python3", "awk", "sed", "tr", "cat", "uname"),
		"scanner": tools("awk", "sed", "tr", "cat", "uname"),
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip(err)
	}
	hardening, err := filepath.Abs(filepath.Join("hooks", "_hardening.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for backend, path := range backends {
		check := func(connector, payload string, want bool) {
			t.Helper()
			cmd := exec.Command(bash, "-c", `set -euo pipefail; . "$1"; defenseclaw_failed_stop_event "$2" "" "$3"`,
				"probe", hardening, connector, payload)
			cmd.Env = append(sanitizedTestEnv(), "PATH="+path)
			err := cmd.Run()
			if got := err == nil; got != want {
				t.Errorf("%s backend, %s %s: stop event = %v, want %v (%v)", backend, connector, payload, got, want, err)
			}
		}
		check("claudecode", `{"hook_event_name":"Stop"}`, true)
		check("devin", `{"event":"Stop"}`, true)
		for _, p := range malformedStopEventProbes() {
			check(p.connector, p.payload, false)
		}
	}
}

type stopHookRun struct {
	code   int
	stdout string
	stderr string
	log    string
}

// runPerUserHookForStop runs a rendered per-user hook whose gateway answers
// reply, with automatic gateway start off.
func runPerUserHookForStop(t *testing.T, c Connector, script string, args []string, stdin, reply string, extraEnv ...string) stopHookRun {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if strings.HasPrefix(reply, "exit:") {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		statusText, body, ok := strings.Cut(reply, "|")
		status, err := strconv.Atoi(statusText)
		if !ok || err != nil || status < 100 || status > 599 {
			t.Errorf("invalid test gateway reply %q", reply)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	hooksDir := t.TempDir()
	if err := writePerUserHooksForTestFailMode(hooksDir, listener.Addr().String(), "stop-scoped-token", c, extraEnv); err != nil {
		t.Fatalf("write hooks: %v", err)
	}
	hookPath := filepath.Join(hooksDir, script)
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	env := make([]string, 0, 64)
	for _, entry := range sanitizedTestEnv() {
		if name, _, _ := strings.Cut(entry, "="); name != "HOME" {
			env = append(env, entry)
		}
	}
	env = append(env, "HOME="+home, "DEFENSECLAW_HOME="+dataDir, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
	env = append(env, extraEnv...)
	if strings.Contains(strings.Join(extraEnv, " "), "DC_TEST_NO_TOKEN=1") {
		tokens, _ := filepath.Glob(filepath.Join(hooksDir, "*.token"))
		dotTokens, _ := filepath.Glob(filepath.Join(hooksDir, ".*token"))
		for _, path := range append(tokens, dotTokens...) {
			_ = os.Remove(path)
		}
	}
	cmd := exec.Command("bash", append([]string{hookPath}, args...)...)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	log, _ := os.ReadFile(filepath.Join(dataDir, "logs", "hook-failures.jsonl"))
	return stopHookRun{code: exitCodeOf(err), stdout: stdout.String(), stderr: stderr.String(), log: string(log)}
}

// #1140 on the per-user shell hooks (Linux and macOS): with fail mode
// closed, a stop event whose gateway is down, answers 5xx or answers
// something unusable gets the neutral allow and is logged as fail mode
// open, so Codex no longer retries a blocked Stop on every model turn. A
// tool call stays blocked, and the fail-open profile is unchanged.
func TestPerUserShellHooksLetAFailedStopEventThrough(t *testing.T) {
	codexArgs := func(event string) []string { return codexBoundShellHookArgsForTest(t, "codex-hook.sh", event)[1:] }
	stops := []struct {
		name      string
		c         Connector
		script    string
		args      []string
		stdin     string
		stdout    string
		noTokenOK bool
	}{
		{"codex Stop", NewCodexConnector(), "codex-hook.sh", codexArgs("Stop"), `{"hook_event_name":"Stop","session_id":"s1"}`, "", true},
		{"codex SubagentStop", NewCodexConnector(), "codex-hook.sh", codexArgs("SubagentStop"), `{"hook_event_name":"SubagentStop","session_id":"s1"}`, "", true},
		{"claude Stop", NewClaudeCodeConnector(), "claude-code-hook.sh", nil, `{"hook_event_name":"Stop","session_id":"s1","stop_hook_active":true}`, "", true},
		{"claude SessionEnd", NewClaudeCodeConnector(), "claude-code-hook.sh", nil, `{"hook_event_name":"SessionEnd","session_id":"s1"}`, "", true},
		{"cursor stop", NewCursorConnector(), "cursor-hook.sh", nil, `{"hook_event_name":"stop","conversation_id":"c1","status":"completed"}`, "{}", true},
		{"devin Stop", NewDevinConnector(), "devin-hook.sh", nil, `{"hook_event_name":"Stop","session_id":"s1"}`, "", false},
		{"kiro Stop", NewKiroConnector(), "kiro-hook.sh", nil, `{"hook_event_name":"Stop","session_id":"s1"}`, "", false},
	}
	replies := map[string]string{"gateway down": "exit:7", "gateway 502": `502|{}`, "unusable answer": `200|<html>proxy</html>`, "gateway 401": `401|{"error":"unauthorized"}`}
	for _, tc := range stops {
		for name, reply := range replies {
			run := runPerUserHookForStop(t, tc.c, tc.script, tc.args, tc.stdin, reply, "DEFENSECLAW_FAIL_MODE=closed")
			if run.code != 0 || strings.TrimSpace(run.stdout) != tc.stdout || !strings.Contains(run.stderr, stopEventNotBlockedLead) {
				t.Errorf("%s, %s: want the neutral allow %q, got exit %d stdout=%q stderr=%q", tc.name, name, tc.stdout, run.code, run.stdout, run.stderr)
			}
			if !strings.Contains(run.log, `"fail_mode":"open"`) || strings.Contains(run.log, `"fail_mode":"closed"`) {
				t.Errorf("%s, %s: want one failure logged as fail mode open: %s", tc.name, name, run.log)
			}
		}
		if tc.noTokenOK {
			run := runPerUserHookForStop(t, tc.c, tc.script, tc.args, tc.stdin, `200|{"action":"allow"}`, "DEFENSECLAW_FAIL_MODE=closed", "DC_TEST_NO_TOKEN=1")
			if run.code != 0 || strings.TrimSpace(run.stdout) != tc.stdout || !strings.Contains(run.stderr, stopEventNotBlockedLead) {
				t.Errorf("%s, missing token: want the neutral allow, got exit %d stdout=%q stderr=%q", tc.name, run.code, run.stdout, run.stderr)
			}
		}
		open := runPerUserHookForStop(t, tc.c, tc.script, tc.args, tc.stdin, "exit:7", "DEFENSECLAW_FAIL_MODE=open")
		if open.code != 0 || !strings.Contains(open.stderr, stopEventNotBlockedLead) {
			t.Errorf("%s, per-user open request: exit %d stderr=%q, want the neutral stop outcome with closed posture", tc.name, open.code, open.stderr)
		}
	}

	codexTool := runPerUserHookForStop(t, NewCodexConnector(), "codex-hook.sh", codexArgs("PreToolUse"), codexPreToolUse, "exit:7", "DEFENSECLAW_FAIL_MODE=closed")
	if !codexBlockAnswer("PreToolUse", codexTool.code, codexTool.stdout) || strings.Contains(codexTool.stderr, stopEventNotBlockedLead) {
		t.Errorf("codex PreToolUse: exit %d stderr=%q, want the fail-closed block", codexTool.code, codexTool.stderr)
	}
	codexPrompt := runPerUserHookForStop(t, NewCodexConnector(), "codex-hook.sh", codexArgs("UserPromptSubmit"), `{"hook_event_name":"UserPromptSubmit","prompt":"hi"}`, `502|{}`, "DEFENSECLAW_FAIL_MODE=closed")
	if !codexBlockAnswer("UserPromptSubmit", codexPrompt.code, codexPrompt.stdout) {
		t.Errorf("codex UserPromptSubmit: exit %d stderr=%q, want the fail-closed block", codexPrompt.code, codexPrompt.stderr)
	}
	// A per-user Claude Code hook blocks a tool call with its own JSON deny
	// and exit 0 (GAP-1074).
	claudeTool := runPerUserHookForStop(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, claudePreToolUse, "exit:7", "DEFENSECLAW_FAIL_MODE=closed")
	if claudeTool.code != 0 || !strings.Contains(claudeTool.stdout, `"permissionDecision":"deny"`) || strings.Contains(claudeTool.stderr, stopEventNotBlockedLead) {
		t.Errorf("claude PreToolUse: exit %d stdout=%q stderr=%q, want the fail-closed JSON deny", claudeTool.code, claudeTool.stdout, claudeTool.stderr)
	}
	// A payload whose two event fields disagree names no stop event.
	devinMixed := runPerUserHookForStop(t, NewDevinConnector(), "devin-hook.sh", nil, `{"hook_event_name":"Stop","event":"PreToolUse"}`, "exit:7", "DEFENSECLAW_FAIL_MODE=closed")
	if devinMixed.code != 2 {
		t.Errorf("devin mixed events: exit %d stderr=%q, want the fail-closed block", devinMixed.code, devinMixed.stderr)
	}
	// An event field that is not a string names no stop event either, on
	// a gateway outage and on an unusable answer.
	for _, reply := range []string{"exit:7", `200|not json`} {
		for _, tc := range []struct {
			c      Connector
			script string
			stdin  string
		}{
			{NewClaudeCodeConnector(), "claude-code-hook.sh", `{"hook_event_name":"Stop","event":false}`},
			{NewClaudeCodeConnector(), "claude-code-hook.sh", `{"hook_event_name":false,"event":"Stop"}`},
			{NewDevinConnector(), "devin-hook.sh", `{"hook_event_name":"Stop","event":false}`},
			{NewDevinConnector(), "devin-hook.sh", `{"hook_event_name":0,"event":"Stop"}`},
			{NewCursorConnector(), "cursor-hook.sh", `{"hook_event_name":"stop","event":false}`},
			{NewKiroConnector(), "kiro-hook.sh", `{"hook_event_name":"Stop","event":{}}`},
		} {
			run := runPerUserHookForStop(t, tc.c, tc.script, nil, tc.stdin, reply, "DEFENSECLAW_FAIL_MODE=closed")
			if strings.Contains(run.stderr, stopEventNotBlockedLead) || strings.Contains(run.log, `"fail_mode":"open"`) {
				t.Errorf("%s %s, reply %s: a malformed event got the stop exception: exit %d stdout=%q stderr=%q", tc.script, tc.stdin, reply, run.code, run.stdout, run.stderr)
			}
			// Cursor has no deny shape for a stop event, so the failure log
			// row, not stdout, shows that the hook took its fail-closed path.
			if !strings.Contains(run.log, `"fail_mode":"closed"`) {
				t.Errorf("%s %s, reply %s: want the fail-closed path logged, got exit %d stdout=%q log=%s", tc.script, tc.stdin, reply, run.code, run.stdout, run.log)
			}
		}
	}
	// The Codex missing-token check runs after the binding check, as in the
	// native runner: a bound Stop whose stdin is not that Stop fails closed.
	for _, stdin := range []string{`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`, `{"hook_event_name":false}`, `not json`, ``} {
		run := runPerUserHookForStop(t, NewCodexConnector(), "codex-hook.sh", codexArgs("Stop"), stdin, `200|{"action":"allow"}`, "DEFENSECLAW_FAIL_MODE=closed", "DC_TEST_NO_TOKEN=1")
		if run.code != 2 || strings.Contains(run.stderr, stopEventNotBlockedLead) || !strings.Contains(run.stderr, "binding error") {
			t.Errorf("codex Stop, missing token, stdin %q: exit %d stderr=%q, want the fail-closed binding error", stdin, run.code, run.stderr)
		}
	}
}

// #1140 in the OpenShell sandbox hooks, which always fail closed: the live
// Codex sandbox repeated its blocked Stop 33 times while the gateway was
// down. A stop event now gets the neutral allow on every failure the
// ingress or the relay can produce; tool calls stay blocked
// (TestSandboxHooksFailClosed).
func TestSandboxHooksLetAFailedStopEventThrough(t *testing.T) {
	cases := []struct {
		provider SandboxArtifactProvider
		version  string
		script   string
		args     []string
		stdin    string
		stdout   string
	}{
		{&ClaudeCodeConnector{}, "2.1.156", "claude-code-hook.sh", nil, `{"hook_event_name":"Stop","session_id":"s1","stop_hook_active":false}`, ""},
		{&CodexConnector{}, "0.146.0", "codex-hook.sh", []string{"--event", "Stop", "--hook-contract", "codex-hooks-v4"}, `{"hook_event_name":"Stop","session_id":"s1"}`, ""},
		{NewCopilotConnector(), "1.0.88", "copilot-hook.sh", []string{"--event", "agentStop"}, `{"sessionId":"s1","timestamp":1790483549431,"cwd":"/work/proj"}`, ""},
		{NewCursorConnector(), "2026.07.23-e383d2b", "cursor-hook.sh", nil, `{"hook_event_name":"stop","conversation_id":"c1","status":"completed"}`, "{}"},
		{NewKiroConnector(), "2.24.1", "kiro-hook.sh", nil, `{"hook_event_name":"Stop","session_id":"s1"}`, ""},
		{NewDevinConnector(), "3000.4.25", "devin-hook.sh", nil, `{"hook_event_name":"Stop","session_id":"s1"}`, ""},
	}
	replies := map[string][]string{
		"ingress-down": {"exit:7", "exit:7"},
		"relay-500":    {`500|placeholder did not resolve`},
		"unauthorized": {`401|{"error":"bad token"}`},
		"not-json":     {`200|<html>proxy</html>`},
		"no-action":    {`200|{"ok":true}`},
	}
	for _, tc := range cases {
		h := newSandboxHookHarness(t, tc.provider, tc.version)
		for name, responses := range replies {
			run := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, map[string]string{SandboxTokenEnv: "tok"}, responses)
			if run.exitCode != 0 || strings.TrimSpace(run.stdout) != tc.stdout || !strings.Contains(run.stderr, stopEventNotBlockedLead) {
				t.Errorf("%s/%s: want the neutral allow %q, got exit %d stdout=%q stderr=%q", tc.script, name, tc.stdout, run.exitCode, run.stdout, run.stderr)
			}
		}
	}
}
