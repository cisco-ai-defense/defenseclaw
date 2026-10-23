// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runLoneHook renders one hook template into an empty directory, so
// _hardening.sh is missing, and runs it with a clean environment whose
// DEFENSECLAW_HOME exists.
func runLoneHook(t *testing.T, name string, data templateData, args ...string) (stdout string, code int) {
	t.Helper()
	body, err := renderHookTemplate(name, data)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, name)
	if err := os.WriteFile(script, body, 0o700); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	var env []string
	for _, entry := range sanitizedTestEnv() {
		if key, _, _ := strings.Cut(entry, "="); key != "HOME" && !strings.HasPrefix(key, "DEFENSECLAW_") {
			env = append(env, entry)
		}
	}
	cmd.Env = append(env, "HOME="+home, "DEFENSECLAW_HOME="+home)
	cmd.Stdin = strings.NewReader(`{}`)
	var out bytes.Buffer
	cmd.Stdout = &out
	code = exitCodeOf(cmd.Run())
	return out.String(), code
}

// An Antigravity PreToolUse hook that cannot load its hardening helper still
// answers: a per-user hook in fail mode closed and a standalone managed hook
// print Antigravity's deny; fail mode open and Secure Client keep the exit
// status and print no decision.
func TestAntigravityHookDeniesWhenItsHelpersAreMissing(t *testing.T) {
	for _, tc := range []struct {
		name string
		data templateData
		deny bool
	}{
		{"per-user closed", templateData{FailMode: "closed"}, true},
		{"per-user open", templateData{FailMode: "open"}, false},
		{"managed standalone", templateData{FailMode: "open", Managed: true}, true},
		{"secure client", templateData{FailMode: "open", Managed: true, SecureClient: true, SecureClientDelivery: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.data.APIAddr, tc.data.TokenFile, tc.data.ScopedToken = "127.0.0.1:1", ".hook-antigravity.token", true
			out, code := runLoneHook(t, "antigravity-hook.sh", tc.data, "PreToolUse")
			if tc.deny {
				if code != 0 || !strings.Contains(out, `"decision":"deny"`) {
					t.Fatalf("exit %d stdout %q, want Antigravity's deny", code, out)
				}
				return
			}
			if code == 0 || strings.Contains(out, `"decision"`) {
				t.Fatalf("exit %d stdout %q, want the failed exit and no decision", code, out)
			}
		})
	}
	// Events other than PreToolUse cannot be denied and keep the failed exit.
	out, code := runLoneHook(t, "antigravity-hook.sh", templateData{APIAddr: "127.0.0.1:1", FailMode: "closed", TokenFile: ".t"}, "Stop")
	if code == 0 || out != "" {
		t.Fatalf("Stop: exit %d stdout %q, want the failed exit and no output", code, out)
	}
}

// A Copilot hook bound to no reviewed event cannot tell preToolUse from
// permissionRequest: a per-user hook in fail mode closed and a standalone
// managed hook print both of Copilot's denies, as the Windows hook does.
func TestCopilotHookWithoutAReviewedEventPrintsBothDenies(t *testing.T) {
	for _, tc := range []struct {
		name string
		data templateData
	}{
		{"per-user closed", templateData{FailMode: "closed"}},
		{"managed standalone", templateData{FailMode: "open", Managed: true}},
	} {
		for _, args := range [][]string{nil, {"--event", "futureEvent"}, {"--event", "PreToolUse"}, {"--event"}} {
			t.Run(tc.name+"/"+strings.Join(args, " "), func(t *testing.T) {
				tc.data.APIAddr, tc.data.TokenFile, tc.data.ScopedToken = "127.0.0.1:1", ".hook-copilot.token", true
				out, code := runLoneHook(t, "copilot-hook.sh", tc.data, args...)
				if code != 0 || !strings.Contains(out, `"permissionDecision":"deny"`) || !strings.Contains(out, `"behavior":"deny"`) {
					t.Fatalf("exit %d stdout %q, want both Copilot denies", code, out)
				}
			})
		}
	}
	out, code := runLoneHook(t, "copilot-hook.sh", templateData{APIAddr: "127.0.0.1:1", FailMode: "open", TokenFile: ".t"})
	if code != 0 || out != "" {
		t.Fatalf("per-user open: exit %d stdout %q, want the call to run", code, out)
	}
}

// With every helper present, a per-user Copilot hook bound to no reviewed
// event in fail mode closed prints both denies and says how to register it
// again; the gateway is never asked.
func TestPerUserCopilotHookRefusesAnUnboundEvent(t *testing.T) {
	for _, args := range [][]string{nil, {"--event", "futureEvent"}} {
		run := runPerUserHookForStop(t, NewCopilotConnector(), "copilot-hook.sh", args, `{"sessionId":"s"}`,
			`200|{"action":"allow"}`, "DEFENSECLAW_FAIL_MODE=closed")
		if run.code != 0 || !strings.Contains(run.stdout, `"permissionDecision":"deny"`) ||
			!strings.Contains(run.stdout, `"behavior":"deny"`) || !strings.Contains(run.stdout, "defenseclaw setup copilot") {
			t.Fatalf("args %q: exit %d stdout %q stderr %q, want both denies naming defenseclaw setup copilot", args, run.code, run.stdout, run.stderr)
		}
	}
}

// A closed per-user Copilot or Antigravity hook accepts a confirmation only
// with the agent's native ask (Antigravity: force_ask), as the Windows hook
// does; anything else is no
// verdict and is denied. A real ask is passed through.
func TestPerUserHookDeniesAConfirmationWithoutTheNativeAsk(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}
	copilotCall := `{"sessionId":"s","timestamp":1,"cwd":"/tmp","toolName":"bash","toolArgs":"{\"command\":\"echo ok\"}"}`
	antigravityCall := `{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"echo ok","Cwd":"/tmp"}}}`
	for _, tc := range []struct {
		name   string
		c      Connector
		script string
		args   []string
		stdin  string
		reply  string
		want   string
	}{
		{"copilot preToolUse no output", NewCopilotConnector(), "copilot-hook.sh", []string{"--event", "preToolUse"}, copilotCall,
			`200|{"action":"confirm"}`, `"permissionDecision":"deny"`},
		{"copilot preToolUse allow output", NewCopilotConnector(), "copilot-hook.sh", []string{"--event", "preToolUse"}, copilotCall,
			`200|{"action":"confirm","hook_output":{"permissionDecision":"allow"}}`, `"permissionDecision":"deny"`},
		{"copilot permissionRequest no ask", NewCopilotConnector(), "copilot-hook.sh", []string{"--event", "permissionRequest"}, copilotCall,
			`200|{"action":"confirm"}`, `"behavior":"deny"`},
		{"copilot preToolUse ask", NewCopilotConnector(), "copilot-hook.sh", []string{"--event", "preToolUse"}, copilotCall,
			`200|{"action":"confirm","hook_output":{"permissionDecision":"ask","permissionDecisionReason":"check"}}`, `"permissionDecision":"ask"`},
		{"antigravity no output", NewAntigravityConnector(), "antigravity-hook.sh", []string{"PreToolUse"}, antigravityCall,
			`200|{"action":"confirm"}`, `"decision":"deny"`},
		{"antigravity allow output", NewAntigravityConnector(), "antigravity-hook.sh", []string{"PreToolUse"}, antigravityCall,
			`200|{"action":"confirm","hook_output":{"decision":"allow"}}`, `"decision":"deny"`},
		// GAP-0405: a plain ask honors a cached Always Allow grant, so only
		// force_ask is Antigravity's confirmation.
		{"antigravity plain ask", NewAntigravityConnector(), "antigravity-hook.sh", []string{"PreToolUse"}, antigravityCall,
			`200|{"action":"confirm","hook_output":{"decision":"ask","reason":"check"}}`, `"decision":"deny"`},
		{"antigravity force_ask", NewAntigravityConnector(), "antigravity-hook.sh", []string{"PreToolUse"}, antigravityCall,
			`200|{"action":"confirm","hook_output":{"decision":"force_ask","reason":"check"}}`, `"decision":"force_ask"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := runPerUserHookForStop(t, tc.c, tc.script, tc.args, tc.stdin, tc.reply, "DEFENSECLAW_FAIL_MODE=closed")
			if run.code != 0 || !strings.Contains(run.stdout, tc.want) || strings.Count(run.stdout, "\n") != 1 {
				t.Fatalf("exit %d stdout %q stderr %q, want one answer with %s", run.code, run.stdout, run.stderr, tc.want)
			}
		})
	}
}

// Review round 2: an Antigravity hook whose registration lost its event (or
// names one DefenseClaw did not review) denies a tool call in fail mode
// closed before any other check answers it, its helpers missing included.
// Any other input keeps the no-op answer, since Stop reads the same decision
// field, and fail mode open and Secure Client are unchanged.
func TestAntigravityHookDeniesAnUnboundToolCall(t *testing.T) {
	toolCall := `{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"echo ok"}}}`
	for _, tc := range []struct {
		name  string
		data  templateData
		args  []string
		stdin string
		want  string
	}{
		{"per-user closed", templateData{FailMode: "closed"}, nil, toolCall, "defenseclaw setup antigravity"},
		{"per-user closed unknown event", templateData{FailMode: "closed"}, []string{"pretooluse"}, toolCall, "defenseclaw setup antigravity"},
		{"per-user closed snake case", templateData{FailMode: "closed"}, nil, `{"tool_call" : {"name":"x"}}`, "defenseclaw setup antigravity"},
		{"managed standalone", templateData{FailMode: "open", Managed: true}, nil, toolCall, "administrator"},
		{"sandbox", templateData{FailMode: "closed", Sandbox: true}, nil, toolCall, "without its registered event"},
		{"per-user closed stop input", templateData{FailMode: "closed"}, nil, `{"conversationId":"c1","terminationReason":"done"}`, ""},
		{"per-user closed invocation input", templateData{FailMode: "closed"}, nil, `{"conversationId":"c1","invocationNum":2,"initialNumSteps":0}`, ""},
		// Review round 3: an input that may be a tool call is denied; only
		// one that is clearly another event keeps the neutral answer.
		{"per-user closed no tool call", templateData{FailMode: "closed"}, nil, `{"conversationId":"c1"}`, "defenseclaw setup antigravity"},
		{"per-user closed null tool call", templateData{FailMode: "closed"}, nil, `{"toolCall":null}`, "defenseclaw setup antigravity"},
		{"per-user closed string tool call", templateData{FailMode: "closed"}, nil, `{"toolCall":"run_command"}`, "defenseclaw setup antigravity"},
		{"per-user closed tool step", templateData{FailMode: "closed"}, nil, `{"stepIdx":3,"terminationReason":"done"}`, "defenseclaw setup antigravity"},
		{"per-user closed not json", templateData{FailMode: "closed"}, nil, `run_command terminationReason`, "defenseclaw setup antigravity"},
		{"per-user closed empty", templateData{FailMode: "closed"}, nil, ``, "defenseclaw setup antigravity"},
		{"managed standalone no tool call", templateData{FailMode: "open", Managed: true}, nil, `{"conversationId":"c1"}`, "administrator"},
		{"sandbox no tool call", templateData{FailMode: "closed", Sandbox: true}, nil, `{"conversationId":"c1"}`, "without its registered event"},
		{"per-user open", templateData{FailMode: "open"}, nil, toolCall, ""},
		{"secure client", templateData{FailMode: "open", Managed: true, SecureClient: true, SecureClientDelivery: true}, nil, toolCall, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.data.APIAddr, tc.data.TokenFile, tc.data.ScopedToken = "127.0.0.1:1", ".hook-antigravity.token", true
			body, err := renderHookTemplate("antigravity-hook.sh", tc.data)
			if err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(t.TempDir(), "antigravity-hook.sh")
			if err := os.WriteFile(script, body, 0o700); err != nil {
				t.Fatal(err)
			}
			home := t.TempDir()
			cmd := exec.Command("bash", append([]string{script}, tc.args...)...)
			var env []string
			for _, entry := range sanitizedTestEnv() {
				if key, _, _ := strings.Cut(entry, "="); key != "HOME" && !strings.HasPrefix(key, "DEFENSECLAW_") {
					env = append(env, entry)
				}
			}
			cmd.Env = append(env, "HOME="+home, "DEFENSECLAW_HOME="+home)
			cmd.Stdin = strings.NewReader(tc.stdin)
			var out bytes.Buffer
			cmd.Stdout = &out
			code := exitCodeOf(cmd.Run())
			denied := strings.Contains(out.String(), `"decision":"deny"`)
			if tc.want != "" {
				if code != 0 || !denied || !strings.Contains(out.String(), tc.want) {
					t.Fatalf("exit %d stdout %q, want Antigravity's deny naming %q", code, out.String(), tc.want)
				}
				return
			}
			if denied {
				t.Fatalf("exit %d stdout %q, want no deny", code, out.String())
			}
			if tc.data.FailMode == "closed" && strings.TrimSpace(out.String()) != "{}" {
				t.Fatalf("exit %d stdout %q, want the neutral answer {}", code, out.String())
			}
		})
	}
}
