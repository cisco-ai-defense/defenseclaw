// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"context"
	"io"
	"os/exec"
	"time"
)

const delegationLockTimeout = 2 * time.Minute

// Delegate synchronously invokes the exact installed full hook selected by
// trusted active state. Any state or target failure is an intentional success
// no-op, preserving cached hook behavior after disable or uninstall.
func Delegate(
	executable string,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) int {
	paths, err := CurrentUserPaths()
	if err != nil {
		return 0
	}
	return delegateAt(paths, executable, args, stdin, stdout, stderr)
}

func delegateAt(
	paths Paths,
	executable string,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) int {
	var command *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), delegationLockTimeout)
	defer cancel()
	err := WithGatewayStartLock(ctx, func() error {
		// Setup publishes and disables under this same mutex. Re-read only after
		// acquisition so disable wins cleanly when it linearizes first.
		state, recognized, readErr := readTrustedAt(paths, executable)
		if readErr != nil || !recognized || !state.Active() || !state.DelegationCapable() {
			return nil
		}
		locked, lockErr := LockVerifiedHook(state)
		if lockErr != nil {
			return nil
		}
		defer locked.Close()

		candidate := exec.Command(state.HookPath, args...)
		candidate.Stdin = stdin
		candidate.Stdout = stdout
		candidate.Stderr = stderr
		// Dir and Env intentionally remain unset: os/exec then preserves the
		// launcher's current directory and inherited environment exactly. State
		// and target checks above consume neither project-controlled value.
		if startErr := candidate.Start(); startErr != nil {
			return nil
		}
		command = candidate
		return nil
	})
	if err != nil || command == nil {
		return 0
	}
	if err := command.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}
