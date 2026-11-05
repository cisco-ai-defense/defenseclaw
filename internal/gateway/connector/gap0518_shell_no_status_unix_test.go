// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGAP0518ShellCallStaysClosedAfterVerifiedNoStatus(t *testing.T) {
	for _, conn := range []Connector{NewClaudeCodeConnector(), NewCodexConnector()} {
		t.Run(conn.Name(), func(t *testing.T) {
			invoke := hookArgvConnectorCase(t, conn.Name())
			const protected = "cp a.txt .ssh/authorized_keys"
			invoke.stdin = `{"hook_event_name":"PreToolUse","session_id":"review","tool_name":"Bash","tool_input":{"command":"` + protected + `"}}`
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			installNativeHookPostForHookTest(t, home)
			writeOutageTierConfig(t, home, "config_version: 9\nobservability: {}\nguardrail:\n  mode: action\n")
			seen := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				select {
				case seen <- struct{}{}:
				default:
				}
				select {
				case <-r.Context().Done():
				case <-time.After(10 * time.Second):
				}
			}))
			defer server.Close()
			defer server.CloseClientConnections()
			addr := strings.TrimPrefix(server.URL, "http://")
			if err := os.WriteFile(filepath.Join(home, "gateway.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			hookDir := filepath.Join(home, "hooks")
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, SetupOpts{DataDir: home, APIAddr: addr, APIToken: "review-token", HookFailMode: "open"}, conn); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, invoke.script)}, invoke.args...)...)
			cmd.Stdin = strings.NewReader(invoke.stdin)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
			output, err := cmd.CombinedOutput()
			select {
			case <-seen:
			default:
				t.Fatal("the verified gateway did not receive the call")
			}
			blocked := hookCallBlocked(err, string(output))
			t.Logf("connector=%s blocked=%v", conn.Name(), blocked)
			if !blocked {
				t.Fatal("protected call allowed after verified gateway gave no status")
			}
		})
	}
}
