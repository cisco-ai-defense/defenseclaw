// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// The shell hook runs this helper with HOME set to a scratch folder and
// hands it the account home in hookPostAccountHomeEnv. A late call that names
// a hard link to the keys file stays closed (exit 9) for Codex as for Claude
// Code (GAP-0850); the ordinary twins keep the outage-mode exit 12.
func TestHookPostLateCallIsToldAgainstTheAccountHomeNotTheScratchHome(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	project := filepath.Join(home, "proj")
	scratch := filepath.Join(root, "scratch")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project, scratch} {
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
	if err := os.Link(keys, filepath.Join(project, "hl-keys")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(project, "plain.txt"), filepath.Join(project, "hl-plain")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", scratch)
	names := make([]string, 5000)
	for i := range names {
		names[i] = "f" + itoa(i)
	}
	long := strings.Join(names, " ")

	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(done)
	t.Setenv(hookPostDeadlineEnv, "700")
	t.Setenv(hookPostDataDirEnv, t.TempDir())
	addr := strings.TrimPrefix(server.URL, "http://")
	post := func(path, command string) int {
		body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": project, "tool_name": "Bash",
			"tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		frame := []byte("DCPOST1\x00" + path + "\x00" + string(body) + "\x00Content-Type\x00application/json\x00")
		return runMain([]string{"hook-post", "--api-addr", addr, "--max-time", "1", "--curl-output"},
			bytes.NewReader(frame), new(bytes.Buffer), new(bytes.Buffer))
	}
	// The shell saves its HOME as it got it, so a trailing slash is the same
	// valid home and must not send the scan to the account entry.
	for _, saved := range []string{home, home + "/"} {
		for _, path := range []string{"/api/v1/codex/hook", "/api/v1/claude-code/hook"} {
			for _, tc := range []struct {
				name, command string
				want          int
			}{
				{"hard link to the keys", "touch hl-keys", hookexec.PerUserPostNoAnswerExit},
				{"hard link first operand", "touch hl-keys " + long, hookexec.PerUserPostNoAnswerExit},
				{"hard link last operand", "touch " + long + " hl-keys", hookexec.PerUserPostNoAnswerExit},
				{"hard link by absolute path", "touch " + filepath.Join(project, "hl-keys"), hookexec.PerUserPostNoAnswerExit},
				{"ordinary late call", "touch " + long, hookexec.PerUserPostLateOrdinaryExit},
				{"hard link of an ordinary file", "touch hl-plain", hookexec.PerUserPostLateOrdinaryExit},
			} {
				t.Run(strings.TrimPrefix(path, "/api/v1/")+" "+tc.name+" saved "+saved[len(home):]+".", func(t *testing.T) {
					t.Setenv(hookPostAccountHomeEnv, saved)
					if got := post(path, tc.command); got != tc.want {
						t.Fatalf("exit %d, want %d", got, tc.want)
					}
				})
			}
		}
	}
}

func TestAccountHomeIsTheSavedHomeThenTheAccountEntry(t *testing.T) {
	saved := filepath.Join(t.TempDir(), "saved")
	t.Setenv(hookPostAccountHomeEnv, saved)
	if got := accountHome(); got != saved {
		t.Fatalf("saved home = %q, want %q", got, saved)
	}
	current, err := user.Current()
	if err != nil || !filepath.IsAbs(current.HomeDir) {
		t.Skip("no account entry for the current user")
	}
	// A trailing slash or doubled separator is the same home, cleaned.
	for _, same := range []string{saved + "/", saved + "//", saved + "/./"} {
		t.Setenv(hookPostAccountHomeEnv, same)
		if got := accountHome(); got != saved {
			t.Errorf("home %q gave %q, want %q", same, got, saved)
		}
	}
	// A relative value or a parent step is not a home: the account entry decides.
	for _, bad := range []string{"", "relative/home", saved + "/../other"} {
		t.Setenv(hookPostAccountHomeEnv, bad)
		if got := accountHome(); got != current.HomeDir {
			t.Errorf("home %q gave %q, want the account entry %q", bad, got, current.HomeDir)
		}
	}
}
