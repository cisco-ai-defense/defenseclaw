// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestCommandOpsStatusSaysALegacyDaemon: a daemon before 1.0.4 has no live
// count in its status; the lifecycle kills it rather than stop it.
func TestCommandOpsStatusSaysALegacyDaemon(t *testing.T) {
	for reply, legacy := range map[string]bool{
		`{"sandboxes":0,"running":0}`:          true,
		`{"sandboxes":1,"running":0,"live":0}`: false,
	} {
		ops, _, alice := opsHost(t, "linux", func(line string) (CommandResult, error) {
			switch {
			case strings.HasSuffix(line, "is-active defenseclaw-sandbox.service"):
				return CommandResult{Stdout: []byte("active\n")}, nil
			case strings.HasSuffix(line, "sandbox status --output json"):
				return CommandResult{Stdout: []byte(reply)}, nil
			}
			return CommandResult{}, nil
		})
		st, err := ops.Status(context.Background(), alice)
		if err != nil || st.Legacy != legacy {
			t.Fatalf("%s: Status = %+v %v", reply, st, err)
		}
		if got := daemonStop(st, StopDaemon|StopSocket); (got&StopKill != 0) != legacy {
			t.Fatalf("%s: stop scope %b", reply, got)
		}
	}
}

// killHost answers systemctl as for a daemon whose main process is pid
// until the kill, and after it next (0: gone, or the socket's next daemon).
func killHost(t *testing.T, pid, next string, killErr error) (*commandUserOps, *scriptRunner, SandboxAccount) {
	t.Helper()
	killed := false
	return opsHost(t, "linux", func(line string) (CommandResult, error) {
		switch {
		case strings.Contains(line, "--user show --property=MainPID --value defenseclaw-sandbox.service"):
			if killed {
				return CommandResult{Stdout: []byte(next + "\n")}, nil
			}
			return CommandResult{Stdout: []byte(pid + "\n")}, nil
		case strings.Contains(line, "--user kill --kill-who=main --signal=SIGKILL defenseclaw-sandbox.service"):
			if killErr != nil {
				return CommandResult{ExitCode: 1}, killErr
			}
			killed = true
		case strings.HasSuffix(line, "is-active defenseclaw-sandbox.service"):
			if pid != "0" {
				return CommandResult{Stdout: []byte("active\n")}, nil
			}
			return CommandResult{ExitCode: 3, Stdout: []byte("inactive\n")}, errors.New("exit 3")
		}
		return CommandResult{}, nil
	})
}

// index is where the first call holding sub ran, -1 when none did.
func (s *scriptRunner) index(sub string) int {
	for i, c := range s.calls {
		if strings.Contains(c, sub) {
			return i
		}
	}
	return -1
}

// TestCommandOpsStopKillsALegacyDaemonFirst: a stop with StopKill sends the
// daemon's main process SIGKILL, so the exit of a daemon before 1.0.4
// (which stops the gateway under a completed MicroVM) never runs, and
// stops its units only once systemd saw that process go (the unit's
// ExecStop then stops nothing). A daemon that does not run is not killed;
// one that cannot be killed, or that systemd still names, stops nothing.
func TestCommandOpsStopKillsALegacyDaemonFirst(t *testing.T) {
	ctx := context.Background()
	const stop = "--user stop defenseclaw-sandbox.socket defenseclaw-sandbox.service"
	const kill = "--user kill --kill-who=main --signal=SIGKILL defenseclaw-sandbox.service"
	poll, wait := daemonKillPoll, daemonKillWait
	t.Cleanup(func() { daemonKillPoll, daemonKillWait = poll, wait })
	daemonKillPoll = time.Millisecond

	for _, next := range []string{"0", "5151"} {
		ops, runner, alice := killHost(t, "4242", next, nil)
		if err := ops.Stop(ctx, alice, StopKill|StopDaemon|StopSocket); err != nil {
			t.Fatalf("next %s: %v", next, err)
		}
		if k, s := runner.index(kill), runner.index(stop); k < 0 || s < k || !strings.HasPrefix(runner.calls[k], "runuser -u alice -- ") {
			t.Fatalf("next %s: kill at %d, stop at %d: %v", next, k, s, runner.calls)
		}
	}

	// Without StopKill (a daemon of 1.0.4, whose exit checks for MicroVMs)
	// nothing is killed.
	ops, runner, alice := killHost(t, "4242", "0", nil)
	if err := ops.Stop(ctx, alice, StopDaemon|StopSocket); err != nil || runner.index(kill) >= 0 || runner.index("MainPID") >= 0 {
		t.Fatalf("plain stop: %v %v", err, runner.calls)
	}

	// No daemon runs: nothing to kill, the units stop.
	ops, runner, alice = killHost(t, "0", "0", nil)
	if err := ops.Stop(ctx, alice, StopKill|StopDaemon|StopSocket); err != nil || runner.index(kill) >= 0 || runner.index(stop) < 0 {
		t.Fatalf("no daemon: %v %v", err, runner.calls)
	}

	// A kill that fails while the daemon runs on stops nothing: its stop
	// would run the old exit.
	ops, runner, alice = killHost(t, "4242", "0", errors.New("Failed to kill unit"))
	if err := ops.Stop(ctx, alice, StopKill|StopDaemon|StopSocket); err == nil || runner.index(stop) >= 0 {
		t.Fatalf("failed kill: %v %v", err, runner.calls)
	}

	// systemd still names the killed process: the stop waits, then gives up
	// with nothing stopped.
	daemonKillWait = 20 * time.Millisecond
	ops, runner, alice = killHost(t, "4242", "4242", nil)
	if err := ops.Stop(ctx, alice, StopKill|StopDaemon|StopSocket); err == nil || !strings.Contains(err.Error(), "still names process 4242") || runner.index(stop) >= 0 {
		t.Fatalf("lingering main process: %v %v", err, runner.calls)
	}

	// A restart stops only the daemon: it is killed first too.
	daemonKillWait = wait
	ops, runner, alice = killHost(t, "4242", "0", nil)
	if err := ops.Stop(ctx, alice, StopKill|StopDaemon); err != nil || runner.index(kill) < 0 || runner.index("--user stop defenseclaw-sandbox.service") < runner.index(kill) {
		t.Fatalf("daemon only: %v %v", err, runner.calls)
	}
}

// TestCommandOpsMacOSStopKillsALegacyDaemonFirst: on macOS the agent's
// process gets SIGKILL before its bootout; an agent that is not loaded or
// not running has nothing to kill, and one that runs on stops nothing.
func TestCommandOpsMacOSStopKillsALegacyDaemonFirst(t *testing.T) {
	ctx := context.Background()
	const kill = "launchctl kill SIGKILL user/1001/com.cisco.defenseclaw.sandbox"
	const bootout = "launchctl bootout user/1001/com.cisco.defenseclaw.sandbox"
	host := func(killRes CommandResult, killErr error, running bool) (*commandUserOps, *scriptRunner, SandboxAccount) {
		return opsHost(t, "darwin", func(line string) (CommandResult, error) {
			switch {
			case line == "launchctl print gui/1001":
				return CommandResult{}, errors.New("not found")
			case strings.HasPrefix(line, kill):
				return killRes, killErr
			case strings.HasPrefix(line, "launchctl print user/1001/com.cisco.defenseclaw.sandbox"):
				if running {
					return CommandResult{Stdout: []byte("com.cisco.defenseclaw.sandbox = {\n\tstate = running\n}\n")}, nil
				}
				return CommandResult{Stdout: []byte("com.cisco.defenseclaw.sandbox = {\n\tstate = not running\n}\n")}, nil
			}
			return CommandResult{}, nil
		})
	}
	ops, runner, alice := host(CommandResult{}, nil, true)
	if err := ops.Stop(ctx, alice, StopKill|StopDaemon|StopSocket); err != nil {
		t.Fatal(err)
	}
	if k, b := runner.index(kill), runner.index(bootout); k < 0 || b < k {
		t.Fatalf("kill at %d, bootout at %d: %v", k, b, runner.calls)
	}
	ops, runner, alice = host(CommandResult{}, nil, true)
	if err := ops.Stop(ctx, alice, StopDaemon|StopSocket); err != nil || runner.index(kill) >= 0 {
		t.Fatalf("plain stop: %v %v", err, runner.calls)
	}
	ops, runner, alice = host(CommandResult{Stderr: []byte("Could not find service")}, errors.New("exit 113"), false)
	if err := ops.Stop(ctx, alice, StopKill|StopDaemon|StopSocket); err != nil || runner.index(bootout) < 0 {
		t.Fatalf("not loaded: %v %v", err, runner.calls)
	}
	ops, runner, alice = host(CommandResult{Stderr: []byte("Operation not permitted")}, errors.New("exit 1"), true)
	if err := ops.Stop(ctx, alice, StopKill|StopDaemon|StopSocket); err == nil || runner.index(bootout) >= 0 {
		t.Fatalf("failed kill: %v %v", err, runner.calls)
	}
}
