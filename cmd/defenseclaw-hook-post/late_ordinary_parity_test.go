// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// TestGAP1188ShellAndNativeLateOrdinaryAgree sends one payload table to the
// native hook (hookexec.Run) and to the shell hook helper (hook-post), both
// against a verified gateway that takes the call and never answers it, with
// the open outage tier. A call follows the outage mode on one path exactly
// when it does on the other: ordinary calls on both, and closed on both for a
// call that either late-call scan finds protected, including a call that only
// the shared protected-reach reader refuses (rel-1-0-10 GAP-1188). An
// ordinary leading cd chain, a PermissionRequest and a relative Codex workdir
// follow the outage mode (the review of 098bcb4da9), and so does an ordinary
// cd at a later step (GAP-1303); their protected twins stay closed.
//
// The native hook runs each row on two of its no-answer paths: the
// restart-window path (lateOrdinaryCheck, with a DefenseClaw home) and
// failNoAnswer (bothLateScansOrdinary, with no home, so no restart window is
// armed). Every native answer must be the no-answer one, so a row closed or
// allowed for another reason cannot pass.
//
// The rows run in parallel against a 700 ms answer deadline; a box loaded so
// far that a connect takes that long would close an ordinary row (a known
// flake risk, kept for the run time).
func TestGAP1188ShellAndNativeLateOrdinaryAgree(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	project := filepath.Join(home, "proj")
	sub := filepath.Join(project, "sub")
	scratch := filepath.Join(root, "scratch")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"), sub, scratch,
		filepath.Join(project, "backend"), filepath.Join(project, "frontend")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{filepath.Join(project, "plain.txt"), filepath.Join(sub, "plain.txt"), filepath.Join(home, ".env")} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range []string{filepath.Join(project, "keylink"), filepath.Join(project, "-keylink"), filepath.Join(sub, "childlink")} {
		if err := os.Symlink(keys, link); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(keys, filepath.Join(project, "hardlink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv(hookPostAccountHomeEnv, home)
	t.Setenv(hookPostDeadlineEnv, "700")
	t.Setenv(hookPostDataDirEnv, t.TempDir())

	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}))
	// The parallel rows run after this function returns: cleanups, run last
	// in, first out, end the handlers and then the server once they are done.
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(done) })
	addr := strings.TrimPrefix(server.URL, "http://")

	payload := func(event, tool string, input map[string]any) string {
		body, err := json.Marshal(map[string]any{"hook_event_name": event, "cwd": project, "tool_name": tool, "tool_input": input})
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	bash := func(command string) string {
		return payload("PreToolUse", "Bash", map[string]any{"command": command})
	}
	permission := func(command string) string {
		return payload("PermissionRequest", "Bash", map[string]any{"command": command})
	}
	read := func(path string) string {
		return payload("PreToolUse", "Read", map[string]any{"file_path": path})
	}
	quoted := func(s string) string {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	type row struct {
		name, kind, event, body string
		ordinary                bool
	}
	rows := []row{
		{"echo", "ordinary", "PreToolUse", bash("echo hi"), true},
		{"ls flags", "ordinary", "PreToolUse", bash("ls -la"), true},
		{"ordinary words that read like a name", "ordinary", "PreToolUse", bash("echo claw defense"), true},
		{"sed print of a plain file", "ordinary", "PreToolUse", bash("sed -n 1,5p plain.txt"), true},
		{"echo of a state folder word", "ordinary", "PreToolUse", bash("echo openclaw"), true},
		{"grep pattern of a state folder word", "ordinary", "PreToolUse", bash("grep -e openclaw plain.txt"), true},
		{"read of a plain file", "ordinary", "PreToolUse", read(filepath.Join(project, "plain.txt")), true},
		{"link to the keys file", "first reader", "PreToolUse", bash("cat keylink"), false},
		{"hard link to the keys file", "first reader", "PreToolUse", bash("cat hardlink"), false},
		{"redirect to a dash-named link", "first reader", "PreToolUse", bash("echo x > -keylink"), false},
		{"keys path", "first reader", "PreToolUse", bash("cat ../.ssh/authorized_keys"), false},
		{"cd then a link of that folder", "first reader", "PreToolUse", bash("cd sub && cat childlink"), false},
		{"known value", "first reader", "PreToolUse", bash("cat $HOME/.ssh/authorized_keys"), false},
		{"read of the keys file", "protected read", "PreToolUse", read(keys), false},
		{"read of a link to the keys file", "protected read", "PreToolUse", read(filepath.Join(project, "keylink")), false},
		{"read of a hard link to the keys file", "protected read", "PreToolUse", read(filepath.Join(project, "hardlink")), false},
		{"argv with a plain file", "second reader only", "PreToolUse", payload("PreToolUse", "Bash", map[string]any{"command": []string{"cat", "plain.txt"}}), false},
		{"duplicate command key, the last one plain", "second reader only", "PreToolUse",
			`{"hook_event_name":"PreToolUse","cwd":` + quoted(project) + `,"tool_name":"Bash","tool_input":{"command":"cat keylink","command":"echo hi"}}`, false},
		{"camel-case tool keys", "second reader only", "PreToolUse",
			`{"hook_event_name":"PreToolUse","cwd":` + quoted(project) + `,"toolName":"Bash","toolInput":{"command":"echo hi"}}`, false},
		// Both readers model these shapes now: the ordinary ones follow the
		// outage mode, the protected twins stay closed.
		{"cd then a plain file", "cd chain", "PreToolUse", bash("cd sub && cat plain.txt"), true},
		{"cd then ls", "cd chain", "PreToolUse", bash("cd sub && ls"), true},
		{"cd to the project then go test", "cd chain", "PreToolUse", bash("cd " + project + " && go test ./..."), true},
		{"cd then ls after a semicolon", "cd chain", "PreToolUse", bash("cd sub; ls"), true},
		{"cd and back", "cd chain", "PreToolUse", bash("cd sub && cd .. && cat plain.txt"), true},
		{"Codex relative workdir", "cd chain", "PreToolUse", payload("PreToolUse", "exec_command", map[string]any{"cmd": "cat plain.txt", "workdir": "sub"}), true},
		{"cd into the SSH folder", "cd chain protected", "PreToolUse", bash("cd ../.ssh && cat authorized_keys"), false},
		{"cd home by tilde", "cd chain protected", "PreToolUse", bash("cd ~/.ssh && cat authorized_keys"), false},
		{"cd up to the home", "cd chain protected", "PreToolUse", bash("cd .. && cat .env"), false},
		{"cd by a variable into the state folder", "cd chain protected", "PreToolUse", bash("cd $HOME/.defenseclaw && ls"), false},
		{"cd twice, then tilde", "cd chain protected", "PreToolUse", bash("cd /x; cd ~/.aws && cat credentials"), false},
		{"cd then a link after a semicolon", "cd chain protected", "PreToolUse", bash("cd sub; cat childlink"), false},
		{"Codex relative workdir into the SSH folder", "cd chain protected", "PreToolUse",
			payload("PreToolUse", "exec_command", map[string]any{"cmd": "cat authorized_keys", "workdir": "../.ssh"}), false},
		// GAP-1303: a cd at a later step.
		{"ls, cd, ls", "later cd", "PreToolUse", bash("ls && cd sub && ls"), true},
		{"cd, make, cd back", "later cd", "PreToolUse", bash("cd sub && make && cd .."), true},
		{"two projects", "later cd", "PreToolUse", bash("cd backend && go test ./... && cd ../frontend && npm test"), true},
		{"later cd into the SSH folder", "later cd protected", "PreToolUse", bash("ls && cd ../.ssh && cat authorized_keys"), false},
		{"later cd up to the home", "later cd protected", "PreToolUse", bash("ls && cd .. && cat .env"), false},
		{"later cd home by tilde", "later cd protected", "PreToolUse", bash("ls && cd ~/.ssh && cat authorized_keys"), false},
		{"later cd by a variable into the state folder", "later cd protected", "PreToolUse", bash("ls && cd $HOME/.defenseclaw && ls"), false},
		{"later cd then a link of that folder", "later cd protected", "PreToolUse", bash("ls && cd sub && cat childlink"), false},
		{"cd, make, cd back, then the link", "later cd protected", "PreToolUse", bash("cd sub && make && cd .. && cat keylink"), false},
		{"permission request later cd", "permission request", "PermissionRequest", permission("ls && cd sub && ls"), true},
		{"permission request later cd into the SSH folder", "permission request protected", "PermissionRequest", permission("ls && cd ../.ssh && cat authorized_keys"), false},
		{"permission request", "permission request", "PermissionRequest", permission("echo hi"), true},
		{"permission request cd chain", "permission request", "PermissionRequest", permission("cd sub && ls"), true},
		{"permission request read of a plain file", "permission request", "PermissionRequest",
			payload("PermissionRequest", "Read", map[string]any{"file_path": filepath.Join(project, "plain.txt")}), true},
		{"permission request link to the keys file", "permission request protected", "PermissionRequest", permission("cat keylink"), false},
		{"permission request cd then a link", "permission request protected", "PermissionRequest", permission("cd sub && cat childlink"), false},
		{"permission request read of the keys file", "permission request protected", "PermissionRequest",
			payload("PermissionRequest", "Read", map[string]any{"file_path": keys}), false},
	}
	connectors := []struct{ name, path, contract string }{
		{"claudecode", "/api/v1/claude-code/hook", ""},
		{"codex", "/api/v1/codex/hook", "codex-hooks-v4"},
	}
	// post posts the row to hook-post and returns its exit status.
	post := func(path, body string) int {
		frame := []byte("DCPOST1\x00" + path + "\x00" + body + "\x00Content-Type\x00application/json\x00")
		return runMain([]string{"hook-post", "--api-addr", addr, "--max-time", "1", "--curl-output"},
			bytes.NewReader(frame), new(bytes.Buffer), new(bytes.Buffer))
	}
	// shellOrdinary reports whether a hook-post exit follows the outage mode
	// (exit 12) rather than the closed no-answer exit 9.
	shellOrdinary := func(t *testing.T, code int) bool {
		t.Helper()
		if code != hookexec.PerUserPostLateOrdinaryExit && code != hookexec.PerUserPostNoAnswerExit {
			t.Fatalf("shell exit %d, want a late-call answer (%d or %d)", code, hookexec.PerUserPostLateOrdinaryExit, hookexec.PerUserPostNoAnswerExit)
		}
		return code == hookexec.PerUserPostLateOrdinaryExit
	}
	// native runs the row through hookexec.Run on one no-answer path and
	// reports whether it follows the outage mode. The answer must be the
	// no-answer one either way: on the restart-window path (a DefenseClaw home)
	// the hook-failures row names the no-answer reason with the outcome the
	// call got; on the failNoAnswer path (no home, so no restart window and no
	// row) the answer names the cause, except an allowed PermissionRequest,
	// which carries no warning (it is no warning event) and so must be empty.
	native := func(t *testing.T, connectorName, contract, event, body string, restartWindow bool) bool {
		t.Helper()
		dcHome := t.TempDir()
		hookDir := filepath.Join(dcHome, "hooks")
		if err := os.MkdirAll(hookDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(hookDir, ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=\"tkn\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		client, err := hookexec.NewPerUserGatewayHTTPClient(10*time.Second, addr)
		if err != nil {
			t.Fatal(err)
		}
		home := ""
		if restartWindow {
			home = dcHome
		}
		var stdout, stderr bytes.Buffer
		code := hookexec.Run(context.Background(), hookexec.Options{
			Connector:         connectorName,
			Event:             event,
			HookContractID:    contract,
			APIAddr:           addr,
			FailMode:          "open",
			OutageFailModeNow: func() string { return "open" },
			Home:              home,
			HookDir:           hookDir,
			HTTPClient:        client,
			StartedAt:         time.Now(),
			Stdin:             strings.NewReader(body),
			Stdout:            &stdout,
			Stderr:            &stderr,
		})
		ordinary := code == 0 && !strings.Contains(stdout.String(), "deny") && !strings.Contains(stdout.String(), `"block"`)
		answer := fmt.Sprintf("code %d stdout=%.300q stderr=%.300q", code, stdout.String(), stderr.String())
		if restartWindow {
			want := map[bool]string{true: "fail_open", false: "fail_closed"}[ordinary]
			raw, _ := os.ReadFile(filepath.Join(dcHome, "logs", "hook-failures.jsonl"))
			var record struct{ Reason, Outcome string }
			if lines := strings.Split(strings.TrimSpace(string(raw)), "\n"); len(raw) == 0 || len(lines) != 1 ||
				json.Unmarshal([]byte(lines[0]), &record) != nil || record.Reason != "gateway did not answer in time" || record.Outcome != want {
				t.Fatalf("restart-window path: hook-failures row %q, want one no-answer row with outcome %s (%s)", raw, want, answer)
			}
		} else if ordinary && event == "PermissionRequest" {
			if stdout.Len() != 0 || stderr.Len() != 0 {
				t.Fatalf("failNoAnswer path: an allowed PermissionRequest prints nothing, got %s", answer)
			}
		} else if !strings.Contains(stdout.String()+stderr.String(), "did not answer in time") {
			t.Fatalf("failNoAnswer path: the answer does not name the no-answer cause: %s", answer)
		}
		return ordinary
	}
	paths := []struct {
		name          string
		restartWindow bool
	}{{"restart-window", true}, {"failNoAnswer", false}}
	for _, connector := range connectors {
		for _, row := range rows {
			t.Run(connector.name+"/"+row.kind+"/"+row.name, func(t *testing.T) {
				t.Parallel()
				shell := shellOrdinary(t, post(connector.path, row.body))
				for _, path := range paths {
					nativeOrdinary := native(t, connector.name, connector.contract, row.event, row.body, path.restartWindow)
					if shell != nativeOrdinary {
						t.Fatalf("%s: shell follows the outage mode=%v, native=%v", path.name, shell, nativeOrdinary)
					}
					if nativeOrdinary != row.ordinary {
						t.Fatalf("%s: both paths follow the outage mode=%v, want %v", path.name, nativeOrdinary, row.ordinary)
					}
				}
			})
		}
	}
	// GAP-0850: the shell hook runs hook-post with HOME set to a scratch
	// folder and hands it the account home; the native hook runs with the
	// account HOME. HOME is process-wide, so one sequential subtest posts
	// every row with the scratch HOME at once, while the parallel rows above
	// wait for this function to return; the native rows then run in parallel
	// with the account HOME.
	accountRows := []row{
		{"hard link to the keys file", "scratch HOME", "PreToolUse", bash("cat hardlink"), false},
		{"cd then a link of that folder", "scratch HOME", "PreToolUse", bash("cd sub && cat childlink"), false},
		{"permission request hard link", "scratch HOME", "PermissionRequest", permission("cat hardlink"), false},
		{"plain file", "scratch HOME", "PreToolUse", bash("cat plain.txt"), true},
		{"cd then a plain file", "scratch HOME", "PreToolUse", bash("cd sub && cat plain.txt"), true},
		{"permission request echo", "scratch HOME", "PermissionRequest", permission("echo hi"), true},
	}
	scratchCodes := make([][]int, len(connectors))
	t.Run("scratch HOME shell posts", func(t *testing.T) {
		t.Setenv("HOME", scratch)
		var wg sync.WaitGroup
		for i, connector := range connectors {
			scratchCodes[i] = make([]int, len(accountRows))
			for j, row := range accountRows {
				wg.Add(1)
				go func() {
					defer wg.Done()
					scratchCodes[i][j] = post(connector.path, row.body)
				}()
			}
		}
		wg.Wait()
	})
	for i, connector := range connectors {
		for j, row := range accountRows {
			t.Run(connector.name+"/"+row.kind+"/"+row.name, func(t *testing.T) {
				t.Parallel()
				shell := shellOrdinary(t, scratchCodes[i][j])
				for _, path := range paths {
					nativeOrdinary := native(t, connector.name, connector.contract, row.event, row.body, path.restartWindow)
					if shell != nativeOrdinary || nativeOrdinary != row.ordinary {
						t.Fatalf("%s: shell (scratch HOME) follows the outage mode=%v, native (account HOME)=%v, want %v",
							path.name, shell, nativeOrdinary, row.ordinary)
					}
				}
			})
		}
	}
}
