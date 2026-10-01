//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	defaultCommandTimeout = 5 * time.Second
	defaultOutputLimit    = 64 << 10
	stderrLimit           = 4 << 10
)

// errOutputLimit reports output past the configured bound.
var errOutputLimit = errors.New("unixidentity: command output exceeds limit")

// commandResult is the bounded outcome of one directory-tool invocation.
type commandResult struct {
	stdout   []byte
	exitCode int
}

// commandRunner runs a trusted directory tool with a cleared environment.
// Tests replace it; production uses runTrustedCommand.
type commandRunner func(ctx context.Context, path string, args []string) (commandResult, error)

// limitedBuffer fails writes past its limit so a hostile or broken
// directory backend cannot grow the guardian's memory without bound.
type limitedBuffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.limit {
		b.exceeded = true
		remaining := b.limit - b.buf.Len()
		if remaining > 0 {
			b.buf.Write(p[:remaining])
		}
		return 0, errOutputLimit
	}
	return b.buf.Write(p)
}

// runTrustedCommand executes path with args, a minimal fixed environment,
// a timeout, and bounded stdout/stderr. A non-zero exit is returned in the
// result, not as an error, so callers can map tool-specific exit codes.
func runTrustedCommand(ctx context.Context, path string, args []string) (commandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, defaultCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "LANG=C"}
	cmd.Dir = "/"
	stdout := &limitedBuffer{limit: defaultOutputLimit}
	stderr := &limitedBuffer{limit: stderrLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if stdout.exceeded {
		return commandResult{}, errOutputLimit
	}
	if ctx.Err() != nil {
		return commandResult{}, fmt.Errorf("unixidentity: %s timed out: %w", filepath.Base(path), ctx.Err())
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return commandResult{stdout: stdout.buf.Bytes(), exitCode: exitErr.ExitCode()}, nil
		}
		return commandResult{}, fmt.Errorf("unixidentity: run %s: %w", filepath.Base(path), err)
	}
	return commandResult{stdout: stdout.buf.Bytes(), exitCode: 0}, nil
}

// validateTrustedTool accepts only a regular, root-owned binary that no
// group or other principal can write, below root-owned ancestors. The
// guardian runs as root, so executing a replaceable binary would hand root
// to whoever could replace it.
func validateTrustedTool(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("unixidentity: tool path %q is not absolute", path)
	}
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("unixidentity: inspect %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unixidentity: %s is a symlink", current)
		}
		if current == filepath.Clean(path) {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				return fmt.Errorf("unixidentity: %s is not an executable regular file", current)
			}
		} else if !info.IsDir() {
			return fmt.Errorf("unixidentity: %s is not a directory", current)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("unixidentity: %s is group/other writable", current)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return fmt.Errorf("unixidentity: %s is not root-owned", current)
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}

// firstTrustedTool returns the first candidate that passes validateTrustedTool.
func firstTrustedTool(candidates ...string) (string, error) {
	var errs []error
	for _, candidate := range candidates {
		if err := validateTrustedTool(candidate); err != nil {
			errs = append(errs, err)
			continue
		}
		return candidate, nil
	}
	return "", errors.Join(errs...)
}
