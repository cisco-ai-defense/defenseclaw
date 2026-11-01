// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// sandbox-visibility:GAP-0028 (issue #1130): a warm allowed PreToolUse call
// of the per-user Claude Code and Codex hooks starts at most 14 processes
// and runs at most 9 programs. The hook folder and data directory lookups
// (2), the private HOME (mktemp), the event or binding read (jq), the POST
// (its substitution, stat, the descriptor writer, the helper and the NUL
// reader), the answer check (awk), the answer read (jq) and the cleanup (rm)
// make 13; the stale-folder sweep that runs on one call in 32 (find) makes
// 14. Before the cut the Claude Code hook started 28 and the Codex hook 45
// (12 programs). The golden test (hook_shell_behaviour_golden_linux_test.go)
// pins that they decide and send the same.
func TestWarmRegisteredHooksStartFewProcesses(t *testing.T) {
	strace, err := exec.LookPath("strace")
	if err != nil {
		t.Skip("strace unavailable")
	}
	if probe := exec.Command(strace, "-qq", "-e", "trace=execve", "-o", os.DevNull, "true"); probe.Run() != nil {
		t.Skip("strace cannot trace on this host")
	}
	for _, tool := range []string{"jq", "awk"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s unavailable", tool)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer server.Close()
	cases := []struct {
		name    string
		conn    Connector
		script  string
		args    []string
		payload string
	}{
		{"claudecode", NewClaudeCodeConnector(), "claude-code-hook.sh", nil,
			`{"hook_event_name":"PreToolUse","session_id":"budget-%d","tool_name":"Bash","tool_input":{"command":"echo ok"}}`},
		{"codex", NewCodexConnector(), "codex-hook.sh", []string{"--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"},
			`{"hook_event_name":"PreToolUse","session_id":"budget-%d","turn_id":"t","tool_name":"Bash","tool_input":{"command":"echo ok"}}`},
	}
	clone := regexp.MustCompile(`^\d+\s+(clone|clone3|fork|vfork)\(.*\)\s*=\s*[1-9]\d*$`)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			installNativeHookPostForHookTest(t, home)
			writeOutageTierConfig(t, home, outageDefaultTierConfig)
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "scoped-test-token", HookFailMode: "open"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c.conn); err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(hookDir, c.script)
			env := append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "KRB5CCNAME=")
			run := func(i int, trace string) string {
				argv := append([]string{script}, c.args...)
				if trace != "" {
					argv = append([]string{strace, "-f", "-qq", "-e", "trace=execve,clone,clone3,fork,vfork", "-o", trace}, argv...)
				}
				cmd := exec.Command(argv[0], argv[1:]...)
				cmd.Stdin = strings.NewReader(fmt.Sprintf(c.payload, i))
				cmd.Env = env
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("warm call %d: %v\n%s", i, err, out)
				}
				return string(out)
			}
			for i := 0; i < 3; i++ {
				run(i, "")
			}
			trace := filepath.Join(t.TempDir(), "trace")
			if out := run(3, trace); strings.Contains(out, "deny") || strings.Contains(out, "block") {
				t.Fatalf("the allowed call was blocked:\n%s", out)
			}
			raw, err := os.ReadFile(trace)
			if err != nil {
				t.Fatal(err)
			}
			processes, programs := 0, []string{}
			for _, line := range strings.Split(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if clone.MatchString(line) && !strings.Contains(line, "CLONE_THREAD") {
					processes++
				}
				if strings.Contains(line, "execve(") && strings.HasSuffix(line, "= 0") {
					if fields := strings.SplitN(line, "\"", 3); len(fields) > 1 {
						programs = append(programs, filepath.Base(fields[1]))
					}
				}
			}
			t.Logf("%s warm call: %d processes, %d programs %v", c.name, processes, len(programs), programs)
			if processes > 14 || len(programs) > 9 {
				t.Fatalf("a warm allowed %s call started %d processes and ran %d programs, want at most 14 and 9: %v",
					c.name, processes, len(programs), programs)
			}
		})
	}
}
