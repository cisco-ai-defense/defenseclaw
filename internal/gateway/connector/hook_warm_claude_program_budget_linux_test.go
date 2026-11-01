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
	"strings"
	"sync"
	"testing"
)

var hookPostForProgramBudget struct {
	once sync.Once
	path string
	err  error
}

// GAP-0267 (issue #1130, g-flood-78): a warm registered Claude Code
// PreToolUse call that the gateway allows runs at most eight programs: the
// hook script, the private temporary folder (mktemp, rm), the hook event
// parser and the answer parser (jq twice), the answer check (awk) and the
// POST helper. The account name, the helper modes, the stdin bound and the
// NUL check start no program of their own.
func TestWarmRegisteredClaudeHookRunsAtMostEightPrograms(t *testing.T) {
	strace, err := exec.LookPath("strace")
	if err != nil {
		t.Skip("strace unavailable")
	}
	if probe := exec.Command(strace, "-qq", "-e", "trace=execve", "-o", os.DevNull, "true"); probe.Run() != nil {
		t.Skip("strace cannot trace on this host")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq unavailable")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer server.Close()
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	hookPostForProgramBudget.once.Do(func() {
		dir, err := os.MkdirTemp("", "defenseclaw-hook-post-budget-")
		if err != nil {
			hookPostForProgramBudget.err = err
			return
		}
		hookPostForProgramBudget.path = filepath.Join(dir, "defenseclaw-hook-post")
		cmd := exec.Command("go", "build", "-o", hookPostForProgramBudget.path, "./cmd/defenseclaw-hook-post")
		cmd.Dir = filepath.Join("..", "..", "..")
		if out, err := cmd.CombinedOutput(); err != nil {
			hookPostForProgramBudget.err = fmt.Errorf("build hook-post: %w: %s", err, out)
		}
	})
	if hookPostForProgramBudget.err != nil {
		t.Fatal(hookPostForProgramBudget.err)
	}
	if err := os.Link(hookPostForProgramBudget.path, filepath.Join(home, ".local", "bin", "defenseclaw-hook-post")); err != nil {
		t.Fatal(err)
	}
	writeOutageTierConfig(t, home, outageDefaultTierConfig)
	hookDir := filepath.Join(home, "hooks")
	opts := SetupOpts{DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "scoped-test-token", HookFailMode: "open"}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewClaudeCodeConnector()); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(hookDir, "claude-code-hook.sh")
	env := append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
	env = append(env, "KRB5CCNAME=")
	run := func(i int, trace string) string {
		cmd := exec.Command(script)
		if trace != "" {
			cmd = exec.Command(strace, "-f", "-qq", "-e", "trace=execve", "-o", trace, script)
		}
		cmd.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":"budget-%d","tool_name":"Bash","tool_input":{"command":"echo ok"}}`, i))
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
	trace := filepath.Join(t.TempDir(), "execve")
	if out := run(3, trace); strings.Contains(out, "deny") || strings.Contains(out, "block") {
		t.Fatalf("the allowed call was blocked:\n%s", out)
	}
	raw, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	var programs []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "execve(") && strings.HasSuffix(strings.TrimSpace(line), "= 0") {
			fields := strings.SplitN(line, "\"", 3)
			if len(fields) > 1 {
				programs = append(programs, filepath.Base(fields[1]))
			}
		}
	}
	t.Logf("programs of the warm call: %d %v", len(programs), programs)
	if len(programs) > 8 {
		t.Fatalf("a warm allowed call ran %d programs, want at most 8: %v", len(programs), programs)
	}
}
