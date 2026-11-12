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
	if err := os.Symlink(project, filepath.Join(root, "proj-link")); err != nil {
		t.Fatal(err)
	}
	// A link to the call folder: "fold/.." reaches the parent of the call folder
	// by file system rules, which a text clean-up of the path does not.
	if err := os.Symlink(project, filepath.Join(project, "fold")); err != nil {
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
	var workdir string
	post := func(path, command string) int {
		input := map[string]any{"command": command}
		if workdir != "" {
			input["workdir"] = workdir
		}
		body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": project, "tool_name": "Bash",
			"tool_input": input})
		if err != nil {
			t.Fatal(err)
		}
		frame := []byte("DCPOST1\x00" + path + "\x00" + string(body) + "\x00Content-Type\x00application/json\x00")
		return runMain([]string{"hook-post", "--api-addr", addr, "--max-time", "1", "--curl-output"},
			bytes.NewReader(frame), new(bytes.Buffer), new(bytes.Buffer))
	}
	// The shell saves its HOME as it got it, so a trailing slash or a parent
	// step is the same valid home by file system rules (a link on the way
	// included) and must not send the scan to another home.
	for _, saved := range []struct{ label, home string }{
		{"plain", home},
		{"trailing slash", home + "/"},
		{"parent step", filepath.Join(root, "h", "proj") + "/.."},
		{"parent step by name", home + "/../h"},
		{"parent step through a link", filepath.Join(root, "proj-link") + "/.."},
	} {
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
				t.Run(strings.TrimPrefix(path, "/api/v1/")+" "+tc.name+" saved "+saved.label, func(t *testing.T) {
					t.Setenv(hookPostAccountHomeEnv, saved.home)
					if got := post(path, tc.command); got != tc.want {
						t.Fatalf("exit %d, want %d", got, tc.want)
					}
				})
			}
		}
	}
	// A relative workdir with a link before a parent step is the folder the
	// file system reaches (here the account home), not the one a text
	// clean-up names (the project): the hard link there stays closed.
	if err := os.Link(keys, filepath.Join(home, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "alias"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "note.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workdir = "fold/.."
	t.Setenv(hookPostAccountHomeEnv, home)
	for _, path := range []string{"/api/v1/codex/hook", "/api/v1/claude-code/hook"} {
		for _, tc := range []struct {
			name, command string
			want          int
		}{
			{"hard link to the keys", "touch alias", hookexec.PerUserPostNoAnswerExit},
			{"hard link first operand", "touch alias " + long, hookexec.PerUserPostNoAnswerExit},
			{"hard link last operand", "touch " + long + " alias", hookexec.PerUserPostNoAnswerExit},
			{"hard link by absolute path", "touch " + filepath.Join(home, "alias"), hookexec.PerUserPostNoAnswerExit},
			{"ordinary file", "touch note.txt", hookexec.PerUserPostLateOrdinaryExit},
			{"ordinary late call", "touch " + long, hookexec.PerUserPostLateOrdinaryExit},
		} {
			t.Run(strings.TrimPrefix(path, "/api/v1/")+" "+tc.name+" relative workdir through a link", func(t *testing.T) {
				if got := post(path, tc.command); got != tc.want {
					t.Fatalf("exit %d, want %d", got, tc.want)
				}
			})
		}
	}
	workdir = ""
	// A saved value that is no usable home (missing folder, relative path, a
	// regular file) holds no protected file of its own. The scan then indexes
	// the homes the call can mean (the account database home, the home of the
	// process, a relative value read against the folder of the call), so a
	// hard link to the keys stays closed (exit 9) and a hard link to an
	// ordinary file keeps the outage-mode exit 12: balanced mode does not
	// block ordinary work. The test account database home is not the decoy
	// home, so the cells stand the decoy home in as the home of the process,
	// except the relative value that names it from the folder of the call.
	for _, saved := range []struct{ label, home, process string }{
		{"missing", filepath.Join(root, "missing"), home},
		{"deeper missing", filepath.Join(root, "missing", "deeper"), home},
		{"relative missing", "relative/home", home},
		{"regular file", filepath.Join(project, "plain.txt"), home},
		{"relative to the call", "..", scratch},
		{"relative through a link to the call", "fold/..", scratch},
	} {
		for _, path := range []string{"/api/v1/codex/hook", "/api/v1/claude-code/hook"} {
			for _, tc := range []struct {
				name, command string
				want          int
			}{
				{"hard link to the keys", "touch hl-keys", hookexec.PerUserPostNoAnswerExit},
				{"hard link first operand", "touch hl-keys " + long, hookexec.PerUserPostNoAnswerExit},
				{"hard link last operand", "touch " + long + " hl-keys", hookexec.PerUserPostNoAnswerExit},
				{"hard link by absolute path", "touch " + filepath.Join(project, "hl-keys"), hookexec.PerUserPostNoAnswerExit},
				{"hard link of an ordinary file", "touch hl-plain", hookexec.PerUserPostLateOrdinaryExit},
				{"ordinary late call", "touch " + long, hookexec.PerUserPostLateOrdinaryExit},
			} {
				t.Run(strings.TrimPrefix(path, "/api/v1/")+" "+tc.name+" unusable saved home "+saved.label, func(t *testing.T) {
					t.Setenv(hookPostAccountHomeEnv, saved.home)
					t.Setenv("HOME", saved.process)
					if got := post(path, tc.command); got != tc.want {
						t.Fatalf("home %q: exit %d, want %d", saved.home, got, tc.want)
					}
				})
			}
		}
	}
}

func TestAccountHomeIsTheSavedHomeThenTheAccountEntry(t *testing.T) {
	saved := filepath.Join(t.TempDir(), "saved")
	// The saved value is handed on as it is: the scan resolves it, or closes.
	for _, same := range []string{saved, saved + "/", saved + "/../saved", "relative/home"} {
		t.Setenv(hookPostAccountHomeEnv, same)
		if got := accountHome(); got != same {
			t.Errorf("saved home %q gave %q, want it unchanged", same, got)
		}
	}
	current, err := user.Current()
	if err != nil || !filepath.IsAbs(current.HomeDir) {
		t.Skip("no account entry for the current user")
	}
	// Only a shell that saved nothing sends the scan to the account entry.
	t.Setenv(hookPostAccountHomeEnv, "")
	if got := accountHome(); got != current.HomeDir {
		t.Errorf("no saved home gave %q, want the account entry %q", got, current.HomeDir)
	}
}
