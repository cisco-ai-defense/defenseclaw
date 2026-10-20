// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A host that a process treats as Secure Client (SecureClientHookDelivery,
// the enterprisehooks process profile) but that is not an authenticated
// Secure Client deployment (SecureClientDeploymentVerified is false: a
// standalone managed host, or a stale or spoofed Secure Client root) gets no
// Secure Client opening: an unset mode renders closed, the hook does not read
// DEFENSECLAW_FAIL_MODE, and a missing token blocks even when the rendered
// mode is open (main-sync review finding 5). An explicit open is the
// administrator's choice, so an unreachable gateway follows it (owner
// decision 2026-10-20).
func TestUnverifiedSecureClientHostKeepsManagedHooksClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows uses the authenticated hook executor")
	}
	saved := SecureClientDeploymentVerified
	SecureClientDeploymentVerified = func() bool { return false }
	t.Cleanup(func() { SecureClientDeploymentVerified = saved })

	for _, conn := range []Connector{NewCodexConnector(), NewClaudeCodeConnector(), NewCursorConnector(), NewKiroConnector()} {
		opts := SetupOpts{ManagedEnterprise: true, SecureClientHookDelivery: true}
		if got := resolveHookFailMode(opts, conn); got != "closed" {
			t.Errorf("%s: unset mode on an unverified Secure Client host = %q, want closed", conn.Name(), got)
		}
		if shellHookSecureClientDelivery(opts) {
			t.Errorf("%s: an unverified host took the Secure Client delivery contract", conn.Name())
		}
	}

	// The rendered Kiro hook bakes its mode; the Codex hook blocks a missing
	// token although its explicit mode is open, and lets a gateway outage
	// through in that mode.
	for _, scenario := range []string{"outage", "missing-token"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"action":"allow"}`))
			}))
			defer server.Close()
			addr := strings.TrimPrefix(server.URL, "http://")
			if scenario == "outage" {
				addr = "127.0.0.1:1"
			}
			home := t.TempDir()
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: addr, APIToken: "scoped-test-token", ManagedEnterprise: true,
				HookFailMode: "open", SecureClientHookDelivery: true}
			for _, conn := range []Connector{NewCodexConnector(), NewKiroConnector()} {
				if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
					t.Fatal(err)
				}
			}
			kiro, err := os.ReadFile(filepath.Join(hookDir, "kiro-hook.sh"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(kiro), "${DEFENSECLAW_FAIL_MODE:-") || !strings.Contains(string(kiro), "_DC_SECURE_CLIENT_DELIVERY=0") {
				t.Fatal("an unverified Secure Client host's managed Kiro hook reads DEFENSECLAW_FAIL_MODE or took the delivery contract")
			}
			if scenario == "missing-token" {
				token, err := HookTokenFilePath(hookDir, "codex")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(token); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", filepath.Join(hookDir, "codex-hook.sh"), "--event", "PreToolUse", "--hook-contract", "codex-hooks-v1")
			cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "DEFENSECLAW_FAIL_MODE=open"}
			out, err := cmd.CombinedOutput()
			blocked := err != nil || strings.Contains(string(out), `"decision":"block"`)
			if want := scenario == "missing-token"; blocked != want {
				t.Fatalf("an unverified Secure Client host's %s: blocked=%t, want %t: %s", scenario, blocked, want, out)
			}
		})
	}
}
