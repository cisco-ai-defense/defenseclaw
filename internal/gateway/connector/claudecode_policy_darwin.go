//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const claudeCodeManagedPreferencesDomain = "com.anthropic.claudecode"

const (
	claudeCodeManagedPreferenceCommandTimeout  = 5 * time.Second
	claudeCodeManagedPreferenceDiagnosticLimit = 64 << 10
)

func claudeCodePlatformManagedSettingsRoot() (string, error) {
	return "/Library/Application Support/ClaudeCode", nil
}

type claudeCodeBoundedCommandBuffer struct {
	buffer   bytes.Buffer
	limit    int64
	exceeded bool
}

func (b *claudeCodeBoundedCommandBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - int64(b.buffer.Len())
	if remaining <= 0 {
		b.exceeded = true
		return 0, fmt.Errorf("command output exceeds %d bytes", b.limit)
	}
	if int64(len(p)) > remaining {
		b.exceeded = true
		written, _ := b.buffer.Write(p[:remaining])
		return written, fmt.Errorf("command output exceeds %d bytes", b.limit)
	}
	return b.buffer.Write(p)
}

func runClaudeCodeManagedPreferenceCommandWithLimits(
	executable string,
	args []string,
	stdin []byte,
	timeout time.Duration,
	outputLimit int64,
) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	stdout := &claudeCodeBoundedCommandBuffer{limit: outputLimit}
	stderr := &claudeCodeBoundedCommandBuffer{limit: claudeCodeManagedPreferenceDiagnosticLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("command %s timed out after %s", executable, timeout)
	}
	// os/exec does not consistently propagate a custom stdout/stderr Writer's
	// error when the child itself exits successfully. Preserve the explicit
	// bound even on those platform/runtime combinations.
	if stdout.exceeded {
		return nil, fmt.Errorf("command output exceeds %d bytes", outputLimit)
	}
	if stderr.exceeded {
		return nil, fmt.Errorf(
			"command diagnostic output exceeds %d bytes",
			claudeCodeManagedPreferenceDiagnosticLimit,
		)
	}
	if err != nil {
		if diagnostic := strings.TrimSpace(stderr.buffer.String()); diagnostic != "" {
			err = fmt.Errorf("%w: %s", err, diagnostic)
		}
		return nil, err
	}
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}
