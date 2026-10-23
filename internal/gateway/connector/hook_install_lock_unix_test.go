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
