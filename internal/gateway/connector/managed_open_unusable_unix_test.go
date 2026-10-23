// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Administrator open covers a named gateway outage. A gateway that answers
// with a bad status or no usable verdict has not granted the tool call.
func TestManagedOpenShellHooksRejectUnusableGatewayAnswers(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl unavailable")
	}
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"malformed", http.StatusOK, "not-json"},
		{"unauthorized", http.StatusUnauthorized, `{"action":"allow"}`},
		{"error-status", http.StatusServiceUnavailable, `{"action":"allow"}`},
	} {
		for _, conn := range hookArgvShellConnectors {
			t.Run(conn.Name()+"/"+tc.name, func(t *testing.T) {
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					w.WriteHeader(tc.code)
					_, _ = w.Write([]byte(tc.body))
				}))
				defer server.Close()
				invoke := hookArgvConnectorCase(t, conn.Name())
				data := t.TempDir()
				hooks := filepath.Join(data, "hooks")
				opts := SetupOpts{
					DataDir: data, APIAddr: strings.TrimPrefix(server.URL, "http://"),
					APIToken: "test-token", ManagedEnterprise: true,
					ManagedHookBinary: "/usr/local/libexec/defenseclaw-hook",
					HookFailMode:      "open", GuardrailMode: "action",
				}
				if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, opts, conn); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("bash", append([]string{filepath.Join(hooks, invoke.script)}, invoke.args...)...)
				cmd.Stdin = strings.NewReader(invoke.stdin)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+data, "DEFENSECLAW_HOME="+data)
				cmd.Env = append(cmd.Env, invoke.env...)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				if requests.Load() == 0 {
					t.Fatalf("hook did not contact gateway: exit=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
				}
				if err == nil && !strings.Contains(stdout.String(), `"deny"`) &&
					!strings.Contains(stdout.String(), `"block"`) {
					t.Fatalf("managed open allowed unusable gateway answer: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
			})
		}
	}
}

// An oversized input is local hook failure, not a gateway outage.
func TestManagedOpenShellHooksRejectOversizedInputs(t *testing.T) {
	for _, conn := range hookArgvShellConnectors {
		t.Run(conn.Name(), func(t *testing.T) {
			invoke := hookArgvConnectorCase(t, conn.Name())
			data := t.TempDir()
			hooks := filepath.Join(data, "hooks")
			opts := SetupOpts{
				DataDir: data, APIAddr: "127.0.0.1:1", APIToken: "test-token",
				ManagedEnterprise: true, ManagedHookBinary: "/usr/local/libexec/defenseclaw-hook",
				HookFailMode: "open", GuardrailMode: "action",
			}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, opts, conn); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", append([]string{filepath.Join(hooks, invoke.script)}, invoke.args...)...)
			cmd.Stdin = strings.NewReader(invoke.stdin)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+data, "DEFENSECLAW_HOME="+data,
				"DEFENSECLAW_HOOK_MAX_BODY=1")
			cmd.Env = append(cmd.Env, invoke.env...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if err == nil && !strings.Contains(stdout.String(), `"deny"`) &&
				!strings.Contains(stdout.String(), `"block"`) {
				t.Fatalf("managed open allowed oversized input: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}
