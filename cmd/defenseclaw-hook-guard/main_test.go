// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

// A copy of this test binary named defenseclaw-hook.exe stands in for the
// launcher: it reports its argv and stdin and exits with a fixed code.
func TestMain(m *testing.M) {
	if strings.EqualFold(filepath.Base(os.Args[0]), "defenseclaw-hook.exe") {
		stdin, _ := io.ReadAll(os.Stdin)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"args": os.Args[1:], "stdin": string(stdin)})
		fmt.Fprint(os.Stderr, "fake launcher stderr")
		os.Exit(7)
	}
	os.Exit(m.Run())
}

func fakeLauncher(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), ".local", "bin", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func runGuard(args []string, stdin string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// The one-line install's PreToolUse guard runs the launcher with the hook
// argv and passes its answer through (GAP-2467: the guard is this small
// GUI-subsystem program, not the console gateway).
func TestHookGuardRunsTheLauncherWithTheHookArgvAndPassesItsAnswer(t *testing.T) {
	launcher := fakeLauncher(t)
	event := `{"session_id":"s","hook_event_name":"PreToolUse"}`
	code, out, errOut := runGuard([]string{"launcher-guard", launcher, "hook", "--connector", "claudecode"}, event)
	var report struct {
		Args  []string `json:"args"`
		Stdin string   `json:"stdin"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("launcher answer %q (exit %d, stderr %q): %v", out, code, errOut, err)
	}
	if code != 7 || !reflect.DeepEqual(report.Args, []string{"hook", "--connector", "claudecode"}) ||
		report.Stdin != event || errOut != "fake launcher stderr" {
		t.Fatalf("exit %d, launcher saw %+v, stderr %q; want the launcher's exit 7, hook argv, event and stderr", code, report, errOut)
	}
}

// A tool call of a turn that began before antivirus removed the launcher is
// blocked, also when the launcher is there but cannot start (GAP-1011).
func TestHookGuardBlocksWhenTheLauncherIsMissingOrCannotStart(t *testing.T) {
	dir := t.TempDir()
	directory := filepath.Join(dir, "dir", "defenseclaw-hook.exe")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, launcher := range map[string]string{
		"missing":     filepath.Join(dir, "gone", "defenseclaw-hook.exe"),
		"a directory": directory,
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runGuard([]string{"launcher-guard", launcher, "hook", "--connector", "claudecode"},
				`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`)
			if code != 2 || stdout != "" || strings.TrimSpace(stderr) != hookguard.MissingMessage {
				t.Fatalf("exit %d, stdout %q, stderr %q; want exit 2 with the guard sentence", code, stdout, stderr)
			}
		})
	}
}

// Cursor starts an imported handler's command without its arguments and
// gets no answer; any other argv starts nothing and is refused with exit 2.
func TestHookGuardGivesCursorNoAnswerAndRefusesAnyOtherArgv(t *testing.T) {
	if code, stdout, stderr := runGuard(nil, `{"hook_event_name":"preToolUse","cursor_version":"1"}`); code != 0 || stdout != "" || stderr != "" {
		t.Fatalf("argument-free start: exit %d, stdout %q, stderr %q; want no answer", code, stdout, stderr)
	}
	launcher := fakeLauncher(t)
	for name, args := range map[string][]string{
		"relative launcher": {"launcher-guard", "defenseclaw-hook.exe", "hook", "--connector", "claudecode"},
		"other program":     {"launcher-guard", filepath.Join(filepath.Dir(launcher), "other.exe"), "hook", "--connector", "claudecode"},
		"other connector":   {"launcher-guard", launcher, "hook", "--connector", "codex"},
		"extra argument":    {"launcher-guard", launcher, "hook", "--connector", "claudecode", "--enterprise-managed"},
		"no launcher":       {"launcher-guard"},
		"hook argv":         {"hook", "--connector", "claudecode"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runGuard(args, `{}`)
			if code != 2 || stdout != "" || !strings.Contains(stderr, "only \"launcher-guard\"") {
				t.Fatalf("exit %d, stdout %q, stderr %q; want the exit-2 refusal", code, stdout, stderr)
			}
		})
	}
}
