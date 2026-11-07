// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// lateOrdinaryProject is a project in a user's home with a link, a hard link
// and a plain file; HOME points at the home (the scan reads it).
func lateOrdinaryProject(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keys, filepath.Join(project, "hardlink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return project
}

func lateOrdinaryPayload(t *testing.T, project, command string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": project, "tool_name": "Bash",
		"tool_input": map[string]any{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// TestGAP0518LateOrdinaryCallFollowsTheOutageMode: a per-user call that its
// verified gateway took and did not answer by the deadline is no longer
// denied when it plainly names nothing protected, in the tier whose outage
// mode is open, with the visible warning and a fail_open row; the strict tier
// stays closed. A call that names the keys file, a link or a hard link to it,
// in a short or a 2000-operand list, stays closed in every tier (the
// verified-gateway-without-status control of the psna-rb review).
func TestGAP0518LateOrdinaryCallFollowsTheOutageMode(t *testing.T) {
	project := lateOrdinaryProject(t)
	shortAnswerBudget(t, 400*time.Millisecond)
	addr := hungGateway(t)
	client, err := NewPerUserGatewayHTTPClient(2*time.Second, addr)
	if err != nil {
		t.Fatal(err)
	}
	words := make([]string, 2000)
	for i := range words {
		words[i] = fmt.Sprintf("lo%d.txt", i)
	}
	long := "touch " + strings.Join(words, " ")
	for _, connector := range []string{"claudecode", "codex"} {
		for _, tc := range []struct {
			name, command string
			mode          string
			blocks        bool
		}{
			{"echo, open tier", "echo hi", "open", false},
			{"build with a redirect and a filter, open tier", "go test ./... 2>&1 | tail -5", "open", false},
			{"2000 operands, open tier", long, "open", false},
			{"echo, strict tier", "echo hi", "closed", true},
			{"2000 operands, strict tier", long, "closed", true},
			{"direct keys path, open tier", "cat ../.ssh/authorized_keys", "open", true},
			{"link to keys, open tier", "cat keylink", "open", true},
			{"hard link to keys, open tier", "cat hardlink", "open", true},
			{"2000 operands with the link last, open tier", long + " keylink", "open", true},
			{"2000 operands with the link first, open tier", "touch keylink " + strings.Join(words, " "), "open", true},
			{"known value, open tier", "cat $HOME/.ssh/authorized_keys", "open", true},
		} {
			t.Run(connector+"/"+tc.name, func(t *testing.T) {
				result, _ := runAgainstGateway(t, connector, addr, func(opts *Options) {
					opts.HTTPClient = client
					opts.FailMode = "open"
					opts.OutageFailModeNow = func() string { return tc.mode }
					opts.Stdin = strings.NewReader(lateOrdinaryPayload(t, project, tc.command))
				})
				if got := blocked(result); got != tc.blocks {
					t.Fatalf("blocks=%v, want %v: code=%d stdout=%.300q stderr=%.300q", got, tc.blocks, result.code, result.stdout, result.stderr)
				}
				if !tc.blocks && !strings.Contains(result.stdout+result.stderr, "did not answer in time") {
					t.Fatalf("no visible warning: stdout=%.300q stderr=%.300q", result.stdout, result.stderr)
				}
			})
		}
	}
}
