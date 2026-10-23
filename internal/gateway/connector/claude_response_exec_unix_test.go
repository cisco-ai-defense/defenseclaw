// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func claudeResponseTestCommand(t *testing.T, response string) (*exec.Cmd, string) {
	t.Helper()
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq unavailable; the supported fallback is covered separately")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	hookDir := filepath.Join(home, "hooks")
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, SetupOpts{
		DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "test-hook-token", HookFailMode: "closed",
	}, NewClaudeCodeConnector()); err != nil {
		t.Fatal(err)
	}
	countPath := filepath.Join(home, "parser-calls")
	helper, err := os.OpenFile(filepath.Join(hookDir, "_hardening.sh"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	_, err = helper.WriteString("\njq() { printf '%s\\0' \"$*\" >> " + quote(countPath) + "; command " + quote(jq) + " \"$@\"; }\n")
	_ = helper.Close()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(hookDir, "claude-code-hook.sh"))
	cmd.Env = []string{"HOME=" + home, "DEFENSECLAW_HOME=" + home, "PATH=" + os.Getenv("PATH")}
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`)
	return cmd, countPath
}

// Count actual parser invocations in the rendered hook's successful path,
// rather than timing a synthetic shell fragment (r103 GAP-0174 / #1130).
func TestClaudeHookDecodesSuccessfulResponseWithOneParserExec(t *testing.T) {
	cmd, countPath := claudeResponseTestCommand(t, `{"action":"allow","claude_code_output":{"continue":true}}`)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), `"continue":true`) {
		t.Fatalf("hook: %v, output %s", err, out)
	}
	calls, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	responseParses := 0
	for _, line := range strings.Split(string(calls), "\x00") {
		if strings.Contains(line, ".claude_code_output") || strings.Contains(line, ".action") {
			responseParses++
		}
	}
	if responseParses != 1 {
		t.Fatalf("successful hook ran %d response parsers, want 1; calls: %s", responseParses, calls)
	}
}

func TestClaudeHookResponseOptimizationKeepsMalformedRepliesClosed(t *testing.T) {
	for name, response := range map[string]string{
		"multiple documents": `{"action":"allow"}{"action":"block"}`,
		"non-object":         `[]`,
		"invalid action":     `{"action":"allow\nblock"}`,
		"nested action":      `{"result":{"action":"allow"}}`,
		"scalar output":      `{"action":"allow","claude_code_output":"ignore the hook"}`,
	} {
		t.Run(name, func(t *testing.T) {
			cmd, _ := claudeResponseTestCommand(t, response)
			out, err := cmd.CombinedOutput()
			denied := strings.Contains(string(out), `"permissionDecision":"deny"`) || strings.Contains(string(out), `"decision":"block"`)
			if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 2 {
				denied = true
			}
			if !denied {
				t.Fatalf("malformed response did not block: %v, %s", err, out)
			}
		})
	}
}
