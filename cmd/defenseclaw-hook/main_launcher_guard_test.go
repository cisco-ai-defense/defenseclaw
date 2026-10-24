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
)

// A copy of this test binary named defenseclaw-hook.exe stands in for the
// stable launcher: it reports its argv and stdin and exits with a fixed code.
func TestMain(m *testing.M) {
	if strings.EqualFold(filepath.Base(os.Args[0]), "defenseclaw-hook.exe") {
		stdin, _ := io.ReadAll(os.Stdin)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"args": os.Args[1:], "stdin": string(stdin)})
		fmt.Fprint(os.Stderr, "fake launcher stderr")
		os.Exit(7)
	}
	os.Exit(m.Run())
}

const launcherMissingSentence = "DefenseClaw blocked this: its Claude Code hook launcher is missing. " +
	"Run the DefenseClaw installer again to repair it."

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
	path := filepath.Join(t.TempDir(), "HookRuntime", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// runHookMain starts this binary's main() with args, as Claude Code starts
// the PreToolUse guard handler.
func runHookMain(t *testing.T, args []string, stdin string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHookMainHelperProcess$")
	cmd.Env = append(os.Environ(), "GO_WANT_HOOK_MAIN_ARGS="+strings.Join(args, "\x1f"))
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, stdout.String(), stderr.String()
}

func TestHookMainHelperProcess(t *testing.T) {
	raw, ok := os.LookupEnv("GO_WANT_HOOK_MAIN_ARGS")
	if !ok {
		t.Skip("helper process")
	}
	os.Args = append(os.Args[:1], strings.Split(raw, "\x1f")...)
	main()
}

// A Claude Code turn that started before antivirus removed the launcher ran
// its tool calls unchecked: the PreToolUse handler started the missing
// launcher, and Claude Code treats a failed start as a non-blocking error.
// The guard handler blocks instead, as the cmd.exe guard of 1.0.1 to 1.0.3
// did, also when the launcher is present but cannot start.
func TestLauncherGuardBlocksWhenTheLauncherIsMissingOrCannotStart(t *testing.T) {
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
			code, stdout, stderr := runHookMain(t,
				[]string{"launcher-guard", launcher, "hook", "--connector", "claudecode"},
				`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`)
			if code != 2 || stdout != "" || strings.TrimSpace(stderr) != launcherMissingSentence {
				t.Fatalf("exit %d, stdout %q, stderr %q; want exit 2 with the guard sentence", code, stdout, stderr)
			}
		})
	}
}

func TestLauncherGuardRunsTheLauncherWithTheHookArgvAndPassesItsAnswer(t *testing.T) {
	launcher := fakeLauncher(t)
	event := `{"session_id":"s","hook_event_name":"PreToolUse"}`
	code, out, errOut := runHookMain(t, []string{"launcher-guard", launcher, "hook", "--connector", "claudecode"}, event)
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

// Any other argv is no guard start: it gets the exit-2 refusal of a start
// without a hook subcommand and starts nothing.
func TestLauncherGuardRefusesAnyOtherArgv(t *testing.T) {
	launcher := fakeLauncher(t)
	for name, args := range map[string][]string{
		"relative launcher": {"launcher-guard", "defenseclaw-hook.exe", "hook", "--connector", "claudecode"},
		"other program":     {"launcher-guard", filepath.Join(filepath.Dir(launcher), "other.exe"), "hook", "--connector", "claudecode"},
		"other connector":   {"launcher-guard", launcher, "hook", "--connector", "codex"},
		"extra argument":    {"launcher-guard", launcher, "hook", "--connector", "claudecode", "--enterprise-managed"},
		"no launcher":       {"launcher-guard"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runHookMain(t, args, `{"hook_event_name":"PreToolUse"}`)
			if code != 2 || stdout != "" || !strings.Contains(stderr, "expected hook") {
				t.Fatalf("exit %d, stdout %q, stderr %q; want the exit-2 refusal and no launcher start", code, stdout, stderr)
			}
		})
	}
}
