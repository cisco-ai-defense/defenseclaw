// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"runtime"
	"syscall"
)

// Windows reports a pipe whose reader went away as ERROR_BROKEN_PIPE (109)
// or ERROR_NO_DATA (232, "The pipe is being closed").
const (
	windowsErrorBrokenPipe syscall.Errno = 109
	windowsErrorNoData     syscall.Errno = 232
)

// isClosedOutputPipe reports whether err means the reader of our output
// stopped early, as with `| head -1` or `| Select-Object -First 1`.
func isClosedOutputPipe(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	if errno == syscall.EPIPE {
		return true
	}
	return runtime.GOOS == "windows" && (errno == windowsErrorBrokenPipe || errno == windowsErrorNoData)
}

// quietClosedOutputPipe turns a write to a closed output pipe into success,
// so a reader that takes only the first lines does not get
// "Error: write /dev/stdout: The pipe is being closed." (GAP-1694).
func quietClosedOutputPipe(err error) error {
	if isClosedOutputPipe(err) {
		return nil
	}
	return err
}
