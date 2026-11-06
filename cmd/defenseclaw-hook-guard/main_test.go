// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

// A copy of this test binary named defenseclaw-hook.exe stands in for the
// launcher: it reports its argv and stdin and exits with a fixed code.
func TestMain(m *testing.M) {
	if strings.EqualFold(filepath.Base(os.Args[0]), "defenseclaw-hook-guard.exe") && os.Getenv("DC_COWORK_TEST_GUARD") == "1" {
		os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	if strings.EqualFold(filepath.Base(os.Args[0]), "defenseclaw-hook.exe") {
		stdin, _ := io.ReadAll(os.Stdin)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"args": os.Args[1:], "stdin": string(stdin)})
		fmt.Fprint(os.Stderr, "fake launcher stderr")
		if bytes.Contains(stdin, []byte(`"allow":true`)) {
			os.Exit(0)
		}
		if bytes.Contains(stdin, []byte(`"deny":true`)) {
			os.Exit(2)
		}
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

func runCoworkGuardProcess(t *testing.T, guard string, args []string, stdin string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(guard, args...)
	cmd.Env = append(os.Environ(), "DC_COWORK_TEST_GUARD=1")
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode(), stdout.String(), stderr.String()
	}
	t.Fatal(err)
	return -1, "", ""
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
// blocked, also when the launcher is there but cannot start (GAP-1011). The
// sentence says "missing" only when nothing is there (cowork-1-0-8 GAP-0086).
func TestHookGuardBlocksWhenTheLauncherIsMissingOrCannotStart(t *testing.T) {
	dir := t.TempDir()
	directory := filepath.Join(dir, "dir", "defenseclaw-hook.exe")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	notAProgram := filepath.Join(dir, "damaged", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(notAProgram), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notAProgram, []byte("this is not a program file\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ launcher, sentence string }{
		"missing":       {filepath.Join(dir, "gone", "defenseclaw-hook.exe"), hookguard.MissingMessage},
		"a directory":   {directory, hookguard.CannotStartMessage},
		"not a program": {notAProgram, hookguard.CannotStartMessage},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runGuard([]string{"launcher-guard", tc.launcher, "hook", "--connector", "claudecode"},
				`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`)
			if code != 2 || stdout != "" || strings.TrimSpace(stderr) != tc.sentence {
				t.Fatalf("exit %d, stdout %q, stderr %q; want exit 2 with %q", code, stdout, stderr, tc.sentence)
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

func TestCoworkGuardKeepsInstalledDecisionsAndCompletedRemoval(t *testing.T) {
	for _, name := range []string{"ordinary", "DC!Ops", "DC%Ops", "DC&Ops", "DC^Ops", "DC(Ops)"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), name)
			dataDir := filepath.Join(root, "account data")
			launcher := fakeLauncher(t)
			moved := filepath.Join(root, "bin", "defenseclaw-hook.exe")
			if err := os.MkdirAll(filepath.Dir(moved), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(launcher, moved); err != nil {
				t.Fatal(err)
			}
			launcher = moved
			guard := filepath.Join(root, "bin", "defenseclaw-hook-guard.exe")
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(self)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(guard, body, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			marker, records := hookguard.CoworkRemovalPaths(dataDir)
			args := []string{hookguard.CoworkSubcommand, dataDir, launcher, "PreToolUse"}
			if _, _, _, ok := hookguard.CoworkArgv(args); !ok {
				t.Fatalf("native guard rejected supported account path %q", root)
			}
			if code, out, _ := runCoworkGuardProcess(t, guard, args, `{"allow":true}`); code != 0 || !strings.Contains(out, "claudecode") {
				t.Fatalf("installed ordinary call: exit %d output %q", code, out)
			}
			if code, _, _ := runCoworkGuardProcess(t, guard, args, `{"deny":true}`); code != 2 {
				t.Fatalf("installed deny: exit %d, want the launcher decision", code)
			}
			if err := os.WriteFile(marker, []byte("removed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, record := range records {
				if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(record, []byte("installed\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if code, _, _ := runCoworkGuardProcess(t, guard, args, `{"deny":true}`); code != 2 {
					t.Fatalf("retained install record: exit %d, want the launcher decision", code)
				}
				if err := os.Remove(record); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(launcher); err != nil {
				t.Fatal(err)
			}
			if code, out, _ := runCoworkGuardProcess(t, guard, args, `{}`); code != 0 || !strings.Contains(out, "Customize") {
				t.Fatalf("completed removal: exit %d output %q, want notice", code, out)
			}
			if code, out, _ := runCoworkGuardProcess(t, guard, args, `{}`); code != 0 || out != "" {
				t.Fatalf("repeated notice: exit %d output %q, want quiet allow", code, out)
			}
			args[3] = "UserPromptSubmit"
			if code, out, _ := runCoworkGuardProcess(t, guard, args, `{}`); code != 0 || !strings.Contains(out, "additionalContext") {
				t.Fatalf("prompt context: exit %d output %q", code, out)
			}
		})
	}
}
