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
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Install and upgrade hold .install.lock. All shell hook surfaces must deny
// during that interval, even if the installed outage mode is open: a gateway
// that is down or gives no usable verdict cannot approve a tool (GAP-0797/8).
func TestPerUserInstallLockClosesEveryShellHook(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl unavailable")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer server.Close()
	type hookCase struct {
		name   string
		conn   Connector
		invoke hookArgvCase
	}
	var cases []hookCase
	for _, conn := range hookArgvShellConnectors {
		cases = append(cases, hookCase{conn.Name(), conn, hookArgvConnectorCase(t, conn.Name())})
	}
	cases = append(cases, hookCase{"copilot-permissionRequest", NewCopilotConnector(), hookArgvCase{
		script: "copilot-hook.sh", args: []string{"--event", "permissionRequest"},
		stdin: `{"sessionId":"s","toolName":"bash","toolArgs":{"command":"echo marker"}}`,
	}})
	for _, invoke := range hookArgvInspectCases() {
		if len(invoke.stdin) <= 4096 {
			cases = append(cases, hookCase{invoke.script, NewCodexConnector(), invoke})
		}
	}
	for _, endpoint := range []struct{ name, addr string }{
		{"stopped", freeAPIAddr(t)},
		{"unauthorized", strings.TrimPrefix(server.URL, "http://")},
	} {
		for _, tc := range cases {
			t.Run(tc.name+"/"+endpoint.name, func(t *testing.T) {
				data := t.TempDir()
				hooks := filepath.Join(data, "hooks")
				if err := os.Mkdir(filepath.Join(data, ".install.lock"), 0o700); err != nil {
					t.Fatal(err)
				}
				opts := SetupOpts{DataDir: data, APIAddr: endpoint.addr, APIToken: "test-token", HookFailMode: "open", GuardrailMode: "action", WorkspaceDir: data}
				if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, opts, tc.conn); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("bash", append([]string{filepath.Join(hooks, tc.invoke.script)}, tc.invoke.args...)...)
				cmd.Stdin = strings.NewReader(tc.invoke.stdin)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+data, "DEFENSECLAW_HOME="+data)
				cmd.Env = append(cmd.Env, tc.invoke.env...)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				if err == nil && !strings.Contains(stdout.String(), `"deny"`) && !strings.Contains(stdout.String(), `"block"`) {
					t.Fatalf("hook allowed while install lock held: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
				if tc.invoke.script == "copilot-hook.sh" {
					field := `"permissionDecision":"deny"`
					if tc.name == "copilot-permissionRequest" {
						field = `"behavior":"deny"`
					}
					if !strings.Contains(stdout.String(), field) {
						t.Fatalf("Copilot did not answer with its event-native denial: stdout=%q stderr=%q", stdout.String(), stderr.String())
					}
				}
			})
		}
	}
}

// GAP-1372 (owner decision 2026-10-24): while this account's installer holds
// .install.lock, a call the running gateway answers keeps the gateway's
// answer in the default and permissive tiers. The Copilot shell hook denied
// it at entry, before the gateway was asked (a benign false block), while the
// other shell hooks kept the allow. Every per-user shell hook now runs the
// call the gateway allowed, in fail mode open and closed; the failures above
// still block.
func TestPerUserInstallLockKeepsEveryShellHooksGatewayAllow(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl unavailable")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer server.Close()
	type hookCase struct {
		name   string
		conn   Connector
		invoke hookArgvCase
	}
	var cases []hookCase
	for _, conn := range hookArgvShellConnectors {
		cases = append(cases, hookCase{conn.Name(), conn, hookArgvConnectorCase(t, conn.Name())})
	}
	cases = append(cases, hookCase{"copilot-permissionRequest", NewCopilotConnector(), hookArgvCase{
		script: "copilot-hook.sh", args: []string{"--event", "permissionRequest"},
		stdin: `{"sessionId":"s","toolName":"bash","toolArgs":{"command":"echo ok"}}`,
	}})
	for _, tc := range cases {
		for _, failMode := range []string{"open", "closed"} {
			t.Run(tc.name+"/"+failMode, func(t *testing.T) {
				data := t.TempDir()
				installNativeGatewayForHookTest(t, data)
				hooks := filepath.Join(data, "hooks")
				opts := SetupOpts{DataDir: data, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "test-token",
					HookFailMode: failMode, GuardrailMode: "action", WorkspaceDir: data}
				if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, opts, tc.conn); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(data, ".install.lock"), 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("bash", append([]string{filepath.Join(hooks, tc.invoke.script)}, tc.invoke.args...)...)
				cmd.Stdin = strings.NewReader(tc.invoke.stdin)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+data, "DEFENSECLAW_HOME="+data, "DEFENSECLAW_AGENT_HOME="+data)
				cmd.Env = append(cmd.Env, tc.invoke.env...)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				code := 0
				if exitErr, ok := err.(*exec.ExitError); ok {
					code = exitErr.ExitCode()
				} else if err != nil {
					t.Fatal(err)
				}
				if shellHookBlocksNatively(tc.invoke.script, code, stdout.String()) ||
					strings.Contains(stdout.String()+stderr.String(), "being installed or upgraded") {
					t.Fatalf("gateway allow refused during the install window: exit %d stdout=%q stderr=%q",
						code, stdout.String(), stderr.String())
				}
			})
		}
	}
}
