//go:build linux

// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package axis

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"
)

func supervise(ctx context.Context, executable string, args []string, cwd string, env []string) (executionResult, error) {
	var stdout, stderr boundedOutput
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir, cmd.Env = cwd, env
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// Request termination, then bound a broken wrapper's wait. This does not
	// establish AXIS cleanup: its pinned noninteractive path does not install
	// the interactive path's TERM handler. WaitDelay kills only the wrapper.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	result := executionResult{exitCode: -1, timedOut: ctx.Err() != nil}
	if cmd.ProcessState != nil {
		result.exitCode = cmd.ProcessState.ExitCode()
	}
	var outTruncated, errTruncated bool
	result.stdout, outTruncated = stdout.snapshot()
	result.stderr, errTruncated = stderr.snapshot()
	result.truncated = outTruncated || errTruncated
	// Signal only through os.Process, never a numeric PID/process group that may
	// have been reused during a cancellation/Wait race. Full descendant custody
	// requires a stronger runtime lifecycle contract and remains a gate.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && err == exitErr {
		return result, nil // Child exit codes are evidence, not prototype errors.
	}
	return result, err
}
