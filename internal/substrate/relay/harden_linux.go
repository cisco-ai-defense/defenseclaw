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

// holdSignals keeps the relay alive against the agent's user (GAP-0116).
// The relay is PID 1 of the actor's PID namespace, and the kernel delivers
// to a namespace's init only the signals it handles: SIGKILL and SIGSTOP
// from inside never arrive, and every other signal is caught here and
// dropped. So the agent can neither stop the relay nor take its port. The
// signals are caught, not ignored, so the agent gets their default handling
// back at exec. It reports whether the relay is PID 1 (outside an actor,
// for example in tests, the agent's user could still SIGKILL it).
func holdSignals() bool {
	ch := make(chan os.Signal, 16)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1,
		syscall.SIGUSR2, syscall.SIGPIPE, syscall.SIGALRM, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)
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
