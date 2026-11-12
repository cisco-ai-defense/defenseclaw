// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// RunAgentCommand is the relay subcommand tmux runs as the pane process: it
// starts the agent on the pane's terminal, waits for it and records its exit
// status in a file before it exits with the same status.
//
// tmux's own #{pane_dead_status} cannot be trusted for this: tmux 3.4 marks a
// pane dead when its terminal closes, before it has reaped the process, and
// sometimes never fills the status in (substrate-1 GAP-0032: on dc-build-1 a
// pane that exited 7 read as dead with no status in 2 of 30 probes, and the
// relay reported -1 in 22 of 60 test runs).
const RunAgentCommand = "run-agent"

// runAgent is `defenseclaw-actor-relay run-agent --status FILE -- ARGV...`.
func runAgent(args []string, stderr io.Writer) int {
	if len(args) < 4 || args[0] != "--status" || args[2] != "--" {
		fmt.Fprintln(stderr, "usage: defenseclaw-actor-relay run-agent --status FILE -- COMMAND [ARG]...")
		return 2
	}
	statusFile, argv := args[1], args[3:]
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Terminal signals (Ctrl-C, Ctrl-\, Ctrl-Z) reach the whole foreground
	// process group, the agent included; this process only must not die of
	// them. They are caught, not ignored, so the agent gets their default
	// handling back at exec.
	sig := make(chan os.Signal, 8)
	signal.Notify(sig, terminalSignals...)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(stderr, "defenseclaw-actor-relay: start %s: %v\n", argv[0], err)
		writeStatus(statusFile, 127)
		return 127
	}
	go func() {
		for s := range sig {
			// A hang-up or a termination is for the agent too; the rest
			// already reached it through the terminal.
			if s == syscall.SIGHUP || s == syscall.SIGTERM {
				_ = cmd.Process.Signal(s)
			}
		}
	}()
	code := 0
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		switch {
		case errors.As(err, &ee):
			code = ee.ExitCode()
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = 128 + int(ws.Signal())
			}
		default:
			code = 1
		}
	}
	writeStatus(statusFile, code)
	return code
}

// writeStatus records code in path atomically.
func writeStatus(path string, code int) {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(code)+"\n"), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// readStatus returns the recorded exit status, if there is one.
func readStatus(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return n, err == nil
}

// agentWrapper is the program tmux runs as the pane process (this binary).
var agentWrapper = func() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}
