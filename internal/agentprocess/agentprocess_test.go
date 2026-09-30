// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package agentprocess

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type table map[int]Process

func (t table) lookup(pid int) (Process, error) {
	if process, ok := t[pid]; ok {
		return process, nil
	}
	return Process{}, errNotFound
}

func chain(names ...string) table {
	// names[0] is the hook (pid 100); each next name is the parent of the
	// previous one, started earlier.
	out := table{}
	for i, name := range names {
		pid := 100 + i
		out[pid] = Process{PID: pid, Parent: pid + 1, Name: name, Start: int64(1000 - i)}
	}
	return out
}

func TestIdentitySkipsShellsAndLaunchersToTheAgent(t *testing.T) {
	cases := []struct {
		name  string
		names []string
		agent int
	}{
		{"direct child of the agent", []string{"defenseclaw-hook", "node", "zsh"}, 101},
		{"through sh -c", []string{"defenseclaw-hook", "sh", "claude", "zsh"}, 102},
		{"through nested shells and env", []string{"defenseclaw-hook", "bash", "env", "dash", "codex", "node"}, 104},
		{"through the Windows launcher and PowerShell", []string{"defenseclaw-hook.exe", "defenseclaw-hook-launcher.exe", "powershell.exe", "node.exe", "explorer.exe"}, 103},
		{"a truncated macOS command name", []string{"defenseclaw-hook", "defenseclaw-hoo", "-zsh", "Cursor Helper (Plugin)"}, 103},
		{"Git Bash and cmd on Windows", []string{"defenseclaw.exe", "BASH.EXE", "cmd.exe", "copilot.exe"}, 103},
	}
	for _, tc := range cases {
		processes := chain(tc.names...)
		got := identityFrom(processes.lookup, 100)
		if want := processes[tc.agent].identity(); got != want {
			t.Errorf("%s: identity = %q, want %q", tc.name, got, want)
		}
	}
}

func TestIdentityIsUnknownWithoutAnAgentAncestor(t *testing.T) {
	cases := map[string]table{
		"only shells up to a session root": chain("defenseclaw-hook", "sh", "zsh", "sshd"),
		"only shells up to launchd":        chain("defenseclaw-hook", "bash", "launchd"),
		"only shells up to an ssh session": chain("defenseclaw-hook", "bash", "-bash", "sshd-session"),
		"PowerShell in Windows Terminal":   chain("defenseclaw-hook.exe", "pwsh.exe", "WindowsTerminal.exe"),
		"only shells up to pid 1":          {100: {PID: 100, Parent: 101, Name: "defenseclaw-hook", Start: 5}, 101: {PID: 101, Parent: 1, Name: "sh", Start: 4}},
		"a missing parent":                 {100: {PID: 100, Parent: 101, Name: "defenseclaw-hook", Start: 5}},
		"more shells than the walk allows": chain("defenseclaw-hook", "sh", "sh", "sh", "sh", "sh", "sh", "sh", "sh", "sh", "node"),
	}
	for name, processes := range cases {
		if got := identityFrom(processes.lookup, 100); got != "" {
			t.Errorf("%s: identity = %q, want unknown", name, got)
		}
	}
}

func TestIdentityUsesAnUnnamedAgentProcess(t *testing.T) {
	processes := chain("defenseclaw-hook", "sh", "")
	if got, want := identityFrom(processes.lookup, 100), processes[102].identity(); got != want {
		t.Fatalf("unnamed agent identity = %q, want process identity %q", got, want)
	}
}

// A parent that started after its child reuses the ID of the real parent,
// which exited; an exited parent is not the agent either.
func TestIdentityRefusesReusedOrExitedParents(t *testing.T) {
	reused := chain("defenseclaw-hook", "sh", "node")
	node := reused[102]
	node.Start = 5000
	reused[102] = node
	if got := identityFrom(reused.lookup, 100); got != "" {
		t.Fatalf("a parent started after its child must not be named: %q", got)
	}
	exited := chain("defenseclaw-hook", "node")
	agent := exited[101]
	agent.Exited = true
	exited[101] = agent
	if got := identityFrom(exited.lookup, 100); got != "" {
		t.Fatalf("an exited parent must not be named: %q", got)
	}
}

// The helper prints the identity it sees; the test runs it through the
// platform's shells and expects its own identity back, because the test
// binary is the helper's nearest non-shell ancestor.
func TestHelperPrintsAgentIdentity(t *testing.T) {
	if os.Getenv("DEFENSECLAW_TEST_AGENT_PROCESS_HELPER") != "1" {
		t.Skip("helper process")
	}
	fmt.Print("identity=" + Identity())
	os.Exit(0)
}

func TestIdentityNamesTheRealAgentProcess(t *testing.T) {
	lookup, done := newLookup()
	self, err := lookup(os.Getpid())
	done()
	if err != nil {
		t.Fatal(err)
	}
	want := self.identity()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := quoteArg(exe) + " -test.run=^TestHelperPrintsAgentIdentity$"
	var commands [][]string
	switch runtime.GOOS {
	case "windows":
		commands = [][]string{
			{exe, "-test.run=^TestHelperPrintsAgentIdentity$"},
			{"cmd.exe", "/c", exe + " -test.run=^TestHelperPrintsAgentIdentity$"},
			{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "& '" + exe + "' '-test.run=^TestHelperPrintsAgentIdentity$'"},
		}
	default:
		// A hook script run through its #! line: the kernel names the
		// process after the script, while its executable is the shell.
		script := filepath.Join(t.TempDir(), "cursor-hook.sh")
		if err := os.WriteFile(script, []byte("#!/bin/sh\n"+helper+"\nstatus=$?\nexit $status\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		commands = [][]string{
			{exe, "-test.run=^TestHelperPrintsAgentIdentity$"},
			{"/bin/sh", "-c", helper},
			{"/bin/sh", "-c", "/bin/sh -c " + quoteArg(helper) + "; true"},
			{script},
		}
	}
	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = append(os.Environ(), "DEFENSECLAW_TEST_AGENT_PROCESS_HELPER=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		text := string(out)
		index := strings.LastIndex(text, "identity=")
		if index < 0 {
			t.Fatalf("%v: no identity in %q", args, text)
		}
		if got := strings.TrimSpace(text[index+len("identity="):]); got != want {
			t.Errorf("%v: identity = %q, want the test process %q", args, got, want)
		}
	}
}

func quoteArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
