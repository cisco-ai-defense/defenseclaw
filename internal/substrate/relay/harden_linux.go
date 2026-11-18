// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// hardenProcess makes the relay non-dumpable: a process of the agent's user
// (the same user) can then neither trace it nor read its memory or open its
// descriptors (/proc/<pid>/fd), so it cannot reach the agent's PTY master
// (GAP-0048). The agent itself is exec'd and dumpable again.
func hardenProcess() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

// heldSignals are the signals the relay catches and drops (GAP-0116): every
// signal whose default action ends or stops a process and that a process can
// catch. The faults (SIGSEGV, SIGBUS, SIGFPE, SIGILL) are caught only when
// sent with kill(2): a real fault in the relay still crashes it. SIGKILL and
// SIGSTOP cannot be caught; only a different user keeps them away
// (relay.agent_user, separate_linux.go).
var heldSignals = []os.Signal{
	syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2,
	syscall.SIGPIPE, syscall.SIGALRM, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU,
	syscall.SIGABRT, syscall.SIGILL, syscall.SIGTRAP, syscall.SIGSYS, syscall.SIGSTKFLT, syscall.SIGXCPU,
	syscall.SIGXFSZ, syscall.SIGVTALRM, syscall.SIGPROF, syscall.SIGIO, syscall.SIGPWR,
	syscall.SIGSEGV, syscall.SIGBUS, syscall.SIGFPE,
}

// holdSignals keeps the relay alive against the agent's signals (GAP-0116):
// each of heldSignals is caught here and dropped, so the agent can neither
// stop the relay nor take its port with one. The signals are caught, not
// ignored, so the agent gets their default handling back at exec.
//
// SIGKILL and SIGSTOP are not covered. A Linux kernel does not deliver them
// to the init of a PID namespace from inside it, but gVisor does (E4 live
// check at 61da1c1a18), so being PID 1 is not the protection: running the
// agent as another user is (relay.agent_user). It reports whether the relay
// is PID 1.
func holdSignals() bool {
	ch := make(chan os.Signal, 16)
	signal.Notify(ch, heldSignals...)
	go func() {
		for range ch {
		}
	}()
	return os.Getpid() == 1
}

// dumpable reports the process's dumpable flag (tests).
func dumpable() (bool, error) {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	return v != 0, err
}
