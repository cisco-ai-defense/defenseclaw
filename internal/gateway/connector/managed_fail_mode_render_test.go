// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rel-1-0-3 GAP-0037: a managed standalone render keeps the closed fail mode
// the managed config resolved, for Cursor in observe mode and for the
// connectors without a fail-closed hook contract of their own. Secure Client
// keeps its rules. The per-user Hermes, Copilot and Antigravity hooks block
// their own failures, so they keep closed (GAP-0150, GAP-0269, r104 W3
// G3-upg). A per-user render records the outage mode of its policy tier
// (oss-outage-open): open only when its caller resolved open.
func TestManagedStandaloneRenderKeepsClosed(t *testing.T) {
	useVerifiedSecureClientDeployment(t)
	standalone := SetupOpts{ManagedEnterprise: true, ManagedHookSocket: "/run/defenseclaw/hook.sock", HookFailMode: "closed", GuardrailMode: "observe"}
	secureClient := SetupOpts{ManagedEnterprise: true, HookFailMode: "closed", GuardrailMode: "observe"}
	perUser := SetupOpts{HookFailMode: "closed", GuardrailMode: "observe"}
	for _, test := range []struct {
		name string
		conn Connector
		opts SetupOpts
		want string
	}{
		{"standalone cursor observe", NewCursorConnector(), standalone, "closed"},
		{"standalone hermes", NewHermesConnector(), standalone, "closed"},
		{"standalone copilot", NewCopilotConnector(), standalone, "closed"},
		{"secure client hermes", NewHermesConnector(), secureClient, "open"},
		{"secure client cursor observe", NewCursorConnector(), secureClient, "closed"},
		{"per-user cursor observe", NewCursorConnector(), perUser, "closed"},
		{"per-user cursor observe, outage open tier", NewCursorConnector(), SetupOpts{HookFailMode: "open", GuardrailMode: "observe"}, "open"},
		{"per-user copilot, outage open tier", NewCopilotConnector(), SetupOpts{HookFailMode: "open"}, "open"},
		{"per-user hermes", NewHermesConnector(), perUser, "closed"},
		{"per-user copilot", NewCopilotConnector(), perUser, "closed"},
		{"per-user antigravity", NewAntigravityConnector(), perUser, "closed"},
		{"secure client copilot", NewCopilotConnector(), secureClient, "open"},
		{"secure client antigravity", NewAntigravityConnector(), secureClient, "open"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := renderedHookFailMode(test.opts, test.conn); got != test.want {
				t.Fatalf("rendered fail mode = %q, want %q", got, test.want)
			}
		})
	}
}

// A managed shell hook takes only its rendered fail mode, and so does a
// per-user hook: neither reads DEFENSECLAW_FAIL_MODE (GAP-0315, 1.0.4 lead
// directive).
func TestManagedShellHooksIgnoreTheEnvironmentFailMode(t *testing.T) {
	for _, name := range []string{
		"antigravity-hook.sh", "claude-code-hook.sh", "codex-hook.sh", "cursor-hook.sh",
		"devin-hook.sh", "hermes-hook.sh", "kiro-hook.sh",
	} {
		for _, managed := range []bool{true, false} {
			scripts, err := renderHookScripts("127.0.0.1:18970", "closed", ".token", []string{name}, managed, strings.TrimSuffix(name, "-hook.sh"), true, "", "", false, false)
			if err != nil {
				t.Fatalf("render %s: %v", name, err)
			}
			for _, script := range scripts {
				if script.name != name {
					continue
				}
				body := string(script.body)
				reads := strings.Contains(body, perUserEnvFailModeRead)
				pinned := strings.Contains(body, "\nFAIL_MODE=\"closed\"")
				if reads || !pinned {
					t.Errorf("%s managed=%v: reads DEFENSECLAW_FAIL_MODE = %v, rendered fail mode pinned = %v", name, managed, reads, pinned)
				}
			}
		}
	}
}

// rel-1-0-2 GAP-0530: a standalone Hermes hook that cannot get a verdict
// blocks the tool call with a message that says why, and a fail mode in the
// environment does not turn a response failure into an allow.
func TestManagedStandaloneHermesHookBlockSaysWhy(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		if _, err := os.Stat("/usr/local/bin/jq"); err != nil {
			t.Skip("jq is required to run the Hermes shell hook")
		}
	}
	f := newHookSocketFixture(t, "dchm", "an answer without a verdict")
	code, stdout, stderr := runStandaloneHermesHook(t, f)
	if code != 0 || !strings.Contains(stdout, `"action":"block"`) ||
		!strings.Contains(stdout, "DefenseClaw blocked this tool call: the DefenseClaw gateway returned an answer DefenseClaw could not use") {
		t.Fatalf("unusable answer: exit %d stdout=%q stderr=%q, want a block that says why", code, stdout, stderr)
	}
	if err := os.Remove(f.socket); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runStandaloneHermesHook(t, f)
	if code != 2 || !strings.Contains(stdout, `"action":"block"`) ||
		!strings.Contains(stdout, "DefenseClaw blocked this tool call: the DefenseClaw gateway service is not running on this computer") {
		t.Fatalf("stopped gateway: exit %d stdout=%q stderr=%q, want a block naming the stopped service", code, stdout, stderr)
	}
}

// runStandaloneHermesHook runs the standalone Hermes hook (runStandaloneShellHook)
// for one tool call.
func runStandaloneHermesHook(t *testing.T, f *hookSocketFixture) (int, string, string) {
	t.Helper()
	return runStandaloneShellHook(t, f, NewHermesConnector(), "hermes-hook.sh", nil,
		`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo marker"}}`)
}

// runStandaloneShellHook renders conn's hooks for a standalone install in
// observe mode on f's socket and runs script once with args and stdin, with
// DEFENSECLAW_FAIL_MODE=open in the environment.
func runStandaloneShellHook(t *testing.T, f *hookSocketFixture, conn Connector, script string, args []string, stdin string) (int, string, string) {
	t.Helper()
	return runStandaloneShellHookInMode(t, f, conn, script, args, stdin, "closed")
}

// runStandaloneShellHookInMode is runStandaloneShellHook with the
// administrator's hook fail mode failMode.
func runStandaloneShellHookInMode(t *testing.T, f *hookSocketFixture, conn Connector, script string, args []string, stdin, failMode string) (int, string, string) {
	t.Helper()
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is required to run shell hooks")
	}
	dataDir := filepath.Join(f.root, "home", ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	opts := SetupOpts{
		DataDir:            dataDir,
		APIAddr:            f.held.Addr().String(),
		HookAPIToken:       "connector-scoped-token",
		HookAPITokenScoped: true,
		ManagedEnterprise:  true,
		HookFailMode:       failMode,
		GuardrailMode:      "observe",
		ManagedHookSocket:  f.socket,
		ManagedServiceUID:  os.Getuid(),
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hookDir, script)
	bakeHookPathForTest(t, hookPath, filepath.Dir(curlPath)+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", append([]string{hookPath}, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+filepath.Join(f.root, "home"), "DEFENSECLAW_FAIL_MODE=open")
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run hook: %v", err)
	}
	return code, stdout.String(), stderr.String()
}
