// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
// the shared protected-reach reader (OrdinaryNoAnswerPayload) refuses
// (rel-1-0-10 GAP-1188).
func TestGAP1188ShellAndNativeLateOrdinaryAgree(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	project := filepath.Join(home, "proj")
	sub := filepath.Join(project, "sub")
	for _, dir := range []string{filepath.Join(home, ".ssh"), sub} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "plain.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
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
	rows := []struct {
		name, kind, event, body string
		ordinary                bool
	}{
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
		{"cd then a plain file", "second reader only", "PreToolUse", bash("cd sub && cat plain.txt"), false},
		{"argv with a plain file", "second reader only", "PreToolUse", payload("PreToolUse", "Bash", map[string]any{"command": []string{"cat", "plain.txt"}}), false},
		{"permission request", "second reader only", "PermissionRequest", payload("PermissionRequest", "Bash", map[string]any{"command": "echo hi"}), false},
		{"duplicate command key, the last one plain", "second reader only", "PreToolUse",
			`{"hook_event_name":"PreToolUse","cwd":` + quoted(project) + `,"tool_name":"Bash","tool_input":{"command":"cat keylink","command":"echo hi"}}`, false},
		{"camel-case tool keys", "second reader only", "PreToolUse",
			`{"hook_event_name":"PreToolUse","cwd":` + quoted(project) + `,"toolName":"Bash","toolInput":{"command":"echo hi"}}`, false},
	}
	connectors := []struct{ name, path, contract string }{
		{"claudecode", "/api/v1/claude-code/hook", ""},
		{"codex", "/api/v1/codex/hook", "codex-hooks-v4"},
	}
	for _, connector := range connectors {
		for _, row := range rows {
			t.Run(connector.name+"/"+row.kind+"/"+row.name, func(t *testing.T) {
				t.Parallel()
				frame := []byte("DCPOST1\x00" + connector.path + "\x00" + row.body + "\x00Content-Type\x00application/json\x00")
				code := runMain([]string{"hook-post", "--api-addr", addr, "--max-time", "1", "--curl-output"},
					bytes.NewReader(frame), new(bytes.Buffer), new(bytes.Buffer))
				if code != hookexec.PerUserPostLateOrdinaryExit && code != hookexec.PerUserPostNoAnswerExit {
					t.Fatalf("shell exit %d, want a late-call answer (%d or %d)", code, hookexec.PerUserPostLateOrdinaryExit, hookexec.PerUserPostNoAnswerExit)
				}
				shellOrdinary := code == hookexec.PerUserPostLateOrdinaryExit

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
				var stdout, stderr bytes.Buffer
				nativeCode := hookexec.Run(context.Background(), hookexec.Options{
					Connector:         connector.name,
					Event:             row.event,
					HookContractID:    connector.contract,
					APIAddr:           addr,
					FailMode:          "open",
					OutageFailModeNow: func() string { return "open" },
					Home:              dcHome,
					HookDir:           hookDir,
					HTTPClient:        client,
					StartedAt:         time.Now(),
					Stdin:             strings.NewReader(row.body),
					Stdout:            &stdout,
					Stderr:            &stderr,
				})
				nativeOrdinary := nativeCode == 0 && !strings.Contains(stdout.String(), "deny") && !strings.Contains(stdout.String(), `"block"`)

				if shellOrdinary != nativeOrdinary {
					t.Fatalf("shell follows the outage mode=%v (exit %d), native=%v (code %d stdout=%.200q stderr=%.200q)",
						shellOrdinary, code, nativeOrdinary, nativeCode, stdout.String(), stderr.String())
				}
				if nativeOrdinary != row.ordinary {
					t.Fatalf("both paths follow the outage mode=%v, want %v (native code %d stdout=%.200q)", nativeOrdinary, row.ordinary, nativeCode, stdout.String())
				}
			})
		}
	}
}
