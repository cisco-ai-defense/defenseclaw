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
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A per-user Copilot CLI, Antigravity or Hermes hook bakes closed for every
// failure and records the outage mode of its policy tier: closed when unset
// or strict, open in the default and permissive tiers (oss-outage-open). No
// hook reads DEFENSECLAW_FAIL_MODE (GAP-0315).
func TestPerUserNativeDenyHookKeepsTheResolvedFailMode(t *testing.T) {
	scripts := map[string]string{"antigravity": "antigravity-hook.sh", "copilot": "copilot-hook.sh", "hermes": "hermes-hook.sh"}
	for _, conn := range nativeDenyConnectors() {
		for _, tc := range []struct {
			name, mode, want string
		}{
			{name: "unset", mode: "", want: "closed"},
			{name: "closed", mode: "closed", want: "closed"},
			{name: "outage open tier", mode: "open", want: "open"},
		} {
			t.Run(conn.Name()+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				opts := SetupOpts{
					DataDir:       filepath.Join(dir, "dc"),
					APIAddr:       "127.0.0.1:18970",
					APIToken:      "tok-test",
					HookFailMode:  tc.mode,
					GuardrailMode: "action",
					WorkspaceDir:  dir,
				}
				hookDir := filepath.Join(dir, "hooks")
				if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
					t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
				}
				body, err := os.ReadFile(filepath.Join(hookDir, scripts[conn.Name()]))
				if err != nil {
					t.Fatalf("read %s: %v", scripts[conn.Name()], err)
				}
				if want := "\nFAIL_MODE=\"closed\"\n"; !strings.Contains(string(body), want) || strings.Contains(string(body), perUserEnvFailModeRead) {
					t.Fatalf("%s does not render %s, or reads DEFENSECLAW_FAIL_MODE", scripts[conn.Name()], want)
				}
				if strings.Contains(string(body), "\nFAIL_MODE=\"open\"\n") {
					t.Fatalf("%s bakes an open fail mode", scripts[conn.Name()])
				}
				flat, err := os.ReadFile(filepath.Join(hookDir, hookConfigSidecarName+"."+conn.Name()))
				if err != nil {
					t.Fatalf("read the %s runtime record: %v", conn.Name(), err)
				}
				if want := "DEFENSECLAW_FAIL_MODE=" + tc.want + "\n"; !strings.Contains(string(flat), want) {
					t.Fatalf("runtime record = %q, want %q", flat, want)
				}
				if got := HookFailClosed(opts, conn); got != (tc.want == "closed") {
					t.Fatalf("HookFailClosed = %v, want %v", got, tc.want == "closed")
				}
			})
		}
	}
}

// runPerUserHook runs a rendered per-user hook with the gateway down and a
// clean DEFENSECLAW_* environment.
func runPerUserHook(t *testing.T, script, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	return runPerUserHookIn(t, t.TempDir(), nil, script, stdin, args...)
}

// runPerUserHookIn is runPerUserHook with HOME and DEFENSECLAW_HOME at home
// and extraEnv added.
func runPerUserHookIn(t *testing.T, home string, extraEnv []string, script, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "DEFENSECLAW_") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(append(env, "DEFENSECLAW_HOME="+home, "HOME="+home), extraEnv...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %s: %v", script, err)
	}
	return out.String(), errb.String(), code
}

// With the gateway down, the per-user Hermes hook rendered with an unset
// fail mode prints Hermes' block directive with the next step, so the tool
// call does not run.
func TestPerUserHermesHookBlocksAToolCallWhileTheGatewayIsDown(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	dir := t.TempDir()
	hookDir := filepath.Join(dir, "hooks")
	opts := SetupOpts{
		DataDir:       filepath.Join(dir, "dc"),
		APIAddr:       freeAPIAddr(t),
		APIToken:      "tok-test",
		GuardrailMode: "action",
		WorkspaceDir:  dir,
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewHermesConnector()); err != nil {
		t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
	}
	out, errOut, _ := runPerUserHook(t, filepath.Join(hookDir, "hermes-hook.sh"),
		`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo ok"}}`)
	if !strings.Contains(out, `"action":"block"`) || !strings.Contains(out, "defenseclaw-gateway ") {
		t.Fatalf("stdout = %q (stderr %q), want a Hermes block directive that names a defenseclaw-gateway next step", out, errOut)
	}
}

// With the gateway down, the per-user Copilot CLI hook rendered with an unset
// or closed (strict tier) outage mode denies preToolUse and permissionRequest
// with Copilot's native deny and a reason that names the next step; the
// outage-open tier lets the call run with a warning that names the fix.
// Copilot's other events cannot block and stay neutral.
func TestPerUserCopilotHookDeniesWhileTheGatewayIsDown(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}
	for _, mode := range []string{"", "closed", "open"} {
		dir := t.TempDir()
		hookDir := filepath.Join(dir, "hooks")
		opts := SetupOpts{
			DataDir:       filepath.Join(dir, "dc"),
			APIAddr:       freeAPIAddr(t),
			APIToken:      "tok-test",
			HookFailMode:  mode,
			GuardrailMode: "action",
			WorkspaceDir:  dir,
		}
		if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewCopilotConnector()); err != nil {
			t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
		}
		script := filepath.Join(hookDir, "copilot-hook.sh")
		for _, tc := range []struct{ event, field, deny string }{
			{"preToolUse", "permissionDecisionReason", `"permissionDecision":"deny"`},
			{"permissionRequest", "message", `"behavior":"deny"`},
			{"sessionStart", "", ""},
		} {
			t.Run("mode "+map[string]string{"": "unset"}[mode]+mode+"/"+tc.event, func(t *testing.T) {
				// The config the outage-open hook reads gives the open tier.
				home := t.TempDir()
				installOutageOpenRuntimeForHookTest(t, home, home)
				out, errOut, code := runPerUserHookIn(t, home, []string{"DEFENSECLAW_GATEWAY_AUTOSTART=0"}, script,
					`{"sessionId":"s","timestamp":1,"cwd":"/tmp","toolName":"bash","toolArgs":"{\"command\":\"echo ok\"}"}`,
					"--event", tc.event)
				if code != 0 {
					t.Fatalf("exit %d, want 0 (stdout %q stderr %q)", code, out, errOut)
				}
				if tc.deny == "" || mode == "open" {
					if strings.TrimSpace(out) != "" {
						t.Fatalf("stdout %q, want no decision (stderr %q)", out, errOut)
					}
					if mode == "open" && tc.deny != "" &&
						(!strings.Contains(errOut, "defenseclaw-gateway start") || !strings.Contains(errOut, "defenseclaw doctor")) {
						t.Fatalf("stderr %q, want the outage warning with its fix", errOut)
					}
					return
				}
				if !strings.Contains(out, tc.deny) {
					t.Fatalf("stdout %q, want %s (stderr %q)", out, tc.deny, errOut)
				}
				var answer map[string]string
				if err := json.Unmarshal([]byte(out), &answer); err != nil {
					t.Fatalf("stdout %q is not one JSON object: %v", out, err)
				}
				if reason := answer[tc.field]; !strings.HasPrefix(reason, "DefenseClaw blocked this tool call: ") ||
					!strings.Contains(reason, "defenseclaw-gateway ") {
					t.Fatalf("%s %q, want a DefenseClaw block that names a defenseclaw-gateway next step", tc.field, reason)
				}
			})
		}
	}
}

// With the gateway down, the per-user Antigravity hook rendered with an unset
// fail mode denies PreToolUse with Antigravity's native deny.
func TestPerUserAntigravityHookDeniesWhileTheGatewayIsDown(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	dir := t.TempDir()
	hookDir := filepath.Join(dir, "hooks")
	opts := SetupOpts{
		DataDir:       filepath.Join(dir, "dc"),
		APIAddr:       freeAPIAddr(t),
		APIToken:      "tok-test",
		GuardrailMode: "action",
		WorkspaceDir:  dir,
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewAntigravityConnector()); err != nil {
		t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
	}
	out, errOut, code := runPerUserHook(t, filepath.Join(hookDir, "antigravity-hook.sh"),
		`{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"echo ok","Cwd":"/tmp"}}}`, "PreToolUse")
	if code != 0 || !strings.Contains(out, `"decision":"deny"`) {
		t.Fatalf("exit %d stdout %q (stderr %q), want Antigravity's native deny", code, out, errOut)
	}
}
